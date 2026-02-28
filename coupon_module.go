package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ─── Models ──────────────────────────────────────────────────────────────────

type Coupon struct {
	ID              int64    `json:"id"`
	Code            string   `json:"code"`
	DiscountType    string   `json:"discount_type"`    // "flat" or "percentage"
	DiscountValue   float64  `json:"discount_value"`   // INR for flat, 1-100 for percentage
	MaxDiscountCap  *float64 `json:"max_discount_cap"` // optional cap for percentage coupons
	MinOrderAmount  float64  `json:"min_order_amount"` // minimum cart total (INR)
	MaxOrderAmount  *float64 `json:"max_order_amount"` // optional max cart total (INR)
	MaxUses         int      `json:"max_uses"`          // 0 = unlimited
	MaxUsesPerUser  int      `json:"max_uses_per_user"` // 0 = unlimited
	TimesUsed       int      `json:"times_used"`
	IsActive        bool     `json:"is_active"`
	CreatedAt       time.Time `json:"created_at"`
}

type couponPayload struct {
	Code           *string  `json:"code"`
	DiscountType   *string  `json:"discount_type"`
	DiscountValue  *float64 `json:"discount_value"`
	MaxDiscountCap *float64 `json:"max_discount_cap"`
	MinOrderAmount *float64 `json:"min_order_amount"`
	MaxOrderAmount *float64 `json:"max_order_amount"`
	MaxUses        *int     `json:"max_uses"`
	MaxUsesPerUser *int     `json:"max_uses_per_user"`
	IsActive       *bool    `json:"is_active"`
}

type applyCouponResponse struct {
	Valid          bool    `json:"valid"`
	CouponID       int64   `json:"coupon_id,omitempty"`
	Code           string  `json:"code,omitempty"`
	DiscountAmount float64 `json:"discount_amount"`
	FinalTotal     float64 `json:"final_total"`
	Message        string  `json:"message"`
}

// ─── Route Registration ──────────────────────────────────────────────────────

func registerCouponRoutes(mux *http.ServeMux) {
	mux.Handle("/api/coupons", ClerkMiddleware(http.HandlerFunc(couponsHandler)))
	mux.Handle("/api/coupons/", ClerkMiddleware(http.HandlerFunc(couponsHandler)))
	mux.Handle("/api/apply-coupon", ClerkMiddleware(http.HandlerFunc(applyCouponHandler)))
	mux.Handle("/api/apply-coupon/", ClerkMiddleware(http.HandlerFunc(applyCouponHandler)))

	// Backward-compatible aliases without /api prefix.
	mux.Handle("/coupons", ClerkMiddleware(http.HandlerFunc(couponsHandler)))
	mux.Handle("/coupons/", ClerkMiddleware(http.HandlerFunc(couponsHandler)))
	mux.Handle("/apply-coupon", ClerkMiddleware(http.HandlerFunc(applyCouponHandler)))
	mux.Handle("/apply-coupon/", ClerkMiddleware(http.HandlerFunc(applyCouponHandler)))
}

// ─── Admin CRUD Router ───────────────────────────────────────────────────────

func couponsHandler(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(r.URL.Path, "/")
	base := "/api/coupons"
	if strings.HasPrefix(path, "/coupons") && !strings.HasPrefix(path, "/api/") {
		base = "/coupons"
	}

	// List / Create – no ID suffix
	if path == base {
		switch r.Method {
		case http.MethodGet:
			handleListCoupons(w, r)
		case http.MethodPost:
			handleCreateCoupon(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	// Routes with /{id}
	rawID := strings.TrimPrefix(path, base+"/")
	if rawID == "" || rawID == path {
		http.NotFound(w, r)
		return
	}
	couponID, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Coupon not found"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		handleGetCoupon(w, r, couponID)
	case http.MethodPut:
		handleUpdateCoupon(w, r, couponID)
	case http.MethodDelete:
		handleDeleteCoupon(w, r, couponID)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ─── Admin: Create Coupon ────────────────────────────────────────────────────

func handleCreateCoupon(w http.ResponseWriter, r *http.Request) {
	if !requireWriteAccess(w, r) {
		return
	}

	repo, err := getProductRepository()
	if err != nil {
		logErrorWithTrace("database initialization failed", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "database initialization failed"})
		return
	}

	var p couponPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON body"})
		return
	}

	if p.Code == nil || strings.TrimSpace(*p.Code) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "code is required"})
		return
	}
	code := strings.ToUpper(strings.TrimSpace(*p.Code))

	discountType := "flat"
	if p.DiscountType != nil {
		dt := strings.ToLower(strings.TrimSpace(*p.DiscountType))
		if dt != "flat" && dt != "percentage" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "discount_type must be 'flat' or 'percentage'"})
			return
		}
		discountType = dt
	}

	discountValue := 0.0
	if p.DiscountValue != nil {
		discountValue = *p.DiscountValue
	}
	if discountValue <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "discount_value must be greater than 0"})
		return
	}
	if discountType == "percentage" && discountValue > 100 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "percentage discount_value cannot exceed 100"})
		return
	}

	minOrderAmount := 0.0
	if p.MinOrderAmount != nil {
		minOrderAmount = *p.MinOrderAmount
	}

	var maxOrderAmount *float64
	if p.MaxOrderAmount != nil && *p.MaxOrderAmount > 0 {
		if *p.MaxOrderAmount < minOrderAmount {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "max_order_amount must be >= min_order_amount"})
			return
		}
		maxOrderAmount = p.MaxOrderAmount
	}

	var maxDiscountCap *float64
	if p.MaxDiscountCap != nil && *p.MaxDiscountCap > 0 {
		maxDiscountCap = p.MaxDiscountCap
	}

	maxUses := 0
	if p.MaxUses != nil {
		maxUses = *p.MaxUses
	}
	maxUsesPerUser := 0
	if p.MaxUsesPerUser != nil {
		maxUsesPerUser = *p.MaxUsesPerUser
	}

	isActive := true
	if p.IsActive != nil {
		isActive = *p.IsActive
	}
	activeInt := 0
	if isActive {
		activeInt = 1
	}

	query := `INSERT INTO coupons(code, discount_type, discount_value, max_discount_cap, min_order_amount, max_order_amount, max_uses, max_uses_per_user, is_active)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`

	var couponID int64
	if repo.dialect == "postgres" {
		err = repo.db.QueryRowContext(r.Context(), rebindQuery(query+" RETURNING id", repo.dialect),
			code, discountType, discountValue, maxDiscountCap, minOrderAmount, maxOrderAmount, maxUses, maxUsesPerUser, activeInt).Scan(&couponID)
	} else {
		res, execErr := repo.exec(r.Context(), query, code, discountType, discountValue, maxDiscountCap, minOrderAmount, maxOrderAmount, maxUses, maxUsesPerUser, activeInt)
		if execErr == nil {
			couponID, _ = res.LastInsertId()
		}
		err = execErr
	}
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "A coupon with this code already exists"})
			return
		}
		logErrorWithTrace("failed to create coupon", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create coupon"})
		return
	}

	coupon, found, err := getCouponByID(r.Context(), repo, couponID)
	if err != nil || !found {
		writeJSON(w, http.StatusCreated, map[string]any{"id": couponID, "status": "created"})
		return
	}
	writeJSON(w, http.StatusCreated, coupon)
}

// ─── Admin: List All Coupons ─────────────────────────────────────────────────

func handleListCoupons(w http.ResponseWriter, r *http.Request) {
	if !requireWriteAccess(w, r) {
		return
	}

	repo, err := getProductRepository()
	if err != nil {
		logErrorWithTrace("database initialization failed", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "database initialization failed"})
		return
	}

	rows, err := repo.query(r.Context(), `
		SELECT id, code, discount_type, discount_value, max_discount_cap, min_order_amount, max_order_amount,
		       max_uses, max_uses_per_user, times_used, is_active, created_at
		FROM coupons ORDER BY id DESC`)
	if err != nil {
		logErrorWithTrace("failed to list coupons", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list coupons"})
		return
	}
	defer rows.Close()

	coupons := make([]Coupon, 0)
	for rows.Next() {
		c, err := scanCouponRow(rows)
		if err != nil {
			logErrorWithTrace("failed to scan coupon", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list coupons"})
			return
		}
		coupons = append(coupons, c)
	}
	if err := rows.Err(); err != nil {
		logErrorWithTrace("failed to iterate coupons", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list coupons"})
		return
	}

	writeJSON(w, http.StatusOK, coupons)
}

// ─── Admin: Get Single Coupon ────────────────────────────────────────────────

func handleGetCoupon(w http.ResponseWriter, r *http.Request, couponID int64) {
	if !requireWriteAccess(w, r) {
		return
	}

	repo, err := getProductRepository()
	if err != nil {
		logErrorWithTrace("database initialization failed", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "database initialization failed"})
		return
	}

	coupon, found, err := getCouponByID(r.Context(), repo, couponID)
	if err != nil {
		logErrorWithTrace("failed to fetch coupon", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to fetch coupon"})
		return
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Coupon not found"})
		return
	}

	writeJSON(w, http.StatusOK, coupon)
}

// ─── Admin: Update Coupon ────────────────────────────────────────────────────

func handleUpdateCoupon(w http.ResponseWriter, r *http.Request, couponID int64) {
	if !requireWriteAccess(w, r) {
		return
	}

	repo, err := getProductRepository()
	if err != nil {
		logErrorWithTrace("database initialization failed", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "database initialization failed"})
		return
	}

	existing, found, err := getCouponByID(r.Context(), repo, couponID)
	if err != nil {
		logErrorWithTrace("failed to fetch coupon", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to fetch coupon"})
		return
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Coupon not found"})
		return
	}

	var p couponPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON body"})
		return
	}

	// Apply partial updates
	code := existing.Code
	if p.Code != nil && strings.TrimSpace(*p.Code) != "" {
		code = strings.ToUpper(strings.TrimSpace(*p.Code))
	}

	discountType := existing.DiscountType
	if p.DiscountType != nil {
		dt := strings.ToLower(strings.TrimSpace(*p.DiscountType))
		if dt != "flat" && dt != "percentage" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "discount_type must be 'flat' or 'percentage'"})
			return
		}
		discountType = dt
	}

	discountValue := existing.DiscountValue
	if p.DiscountValue != nil {
		discountValue = *p.DiscountValue
	}
	if discountValue <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "discount_value must be greater than 0"})
		return
	}
	if discountType == "percentage" && discountValue > 100 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "percentage discount_value cannot exceed 100"})
		return
	}

	minOrderAmount := existing.MinOrderAmount
	if p.MinOrderAmount != nil {
		minOrderAmount = *p.MinOrderAmount
	}

	maxOrderAmount := existing.MaxOrderAmount
	if p.MaxOrderAmount != nil {
		if *p.MaxOrderAmount > 0 {
			maxOrderAmount = p.MaxOrderAmount
		} else {
			maxOrderAmount = nil // explicitly set to 0 removes the cap
		}
	}
	if maxOrderAmount != nil && *maxOrderAmount < minOrderAmount {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "max_order_amount must be >= min_order_amount"})
		return
	}

	maxDiscountCap := existing.MaxDiscountCap
	if p.MaxDiscountCap != nil {
		if *p.MaxDiscountCap > 0 {
			maxDiscountCap = p.MaxDiscountCap
		} else {
			maxDiscountCap = nil
		}
	}

	maxUses := existing.MaxUses
	if p.MaxUses != nil {
		maxUses = *p.MaxUses
	}
	maxUsesPerUser := existing.MaxUsesPerUser
	if p.MaxUsesPerUser != nil {
		maxUsesPerUser = *p.MaxUsesPerUser
	}

	isActive := existing.IsActive
	if p.IsActive != nil {
		isActive = *p.IsActive
	}
	activeInt := 0
	if isActive {
		activeInt = 1
	}

	_, err = repo.exec(r.Context(), `
		UPDATE coupons
		SET code = ?, discount_type = ?, discount_value = ?, max_discount_cap = ?,
		    min_order_amount = ?, max_order_amount = ?, max_uses = ?, max_uses_per_user = ?, is_active = ?
		WHERE id = ?`,
		code, discountType, discountValue, maxDiscountCap,
		minOrderAmount, maxOrderAmount, maxUses, maxUsesPerUser, activeInt, couponID)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "A coupon with this code already exists"})
			return
		}
		logErrorWithTrace("failed to update coupon", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to update coupon"})
		return
	}

	updated, found, err := getCouponByID(r.Context(), repo, couponID)
	if err != nil || !found {
		writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// ─── Admin: Delete Coupon ────────────────────────────────────────────────────

func handleDeleteCoupon(w http.ResponseWriter, r *http.Request, couponID int64) {
	if !requireWriteAccess(w, r) {
		return
	}

	repo, err := getProductRepository()
	if err != nil {
		logErrorWithTrace("database initialization failed", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "database initialization failed"})
		return
	}

	res, err := repo.exec(r.Context(), `DELETE FROM coupons WHERE id = ?`, couponID)
	if err != nil {
		logErrorWithTrace("failed to delete coupon", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to delete coupon"})
		return
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Coupon not found"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// ─── User: Apply Coupon ──────────────────────────────────────────────────────

func applyCouponHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user, ok := authenticatedAppUser(w, r)
	if !ok {
		return
	}

	repo, err := getProductRepository()
	if err != nil {
		logErrorWithTrace("database initialization failed", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "database initialization failed"})
		return
	}

	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON body"})
		return
	}
	code := strings.ToUpper(strings.TrimSpace(body.Code))
	if code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "coupon code is required"})
		return
	}

	// Compute cart total server-side (don't trust client)
	cartID, err := getOrCreateCartID(r.Context(), repo, user.ID)
	if err != nil {
		logErrorWithTrace("failed to get cart", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to fetch cart"})
		return
	}
	items, err := getCartItemsForOrder(r.Context(), repo, cartID)
	if err != nil {
		logErrorWithTrace("failed to fetch cart items", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to fetch cart"})
		return
	}
	if len(items) == 0 {
		writeJSON(w, http.StatusBadRequest, applyCouponResponse{
			Valid:   false,
			Message: "Cart is empty",
		})
		return
	}

	cartTotalINR := float64(calcCartTotalINR(items))

	resp, err := validateAndCalcDiscount(r.Context(), repo, code, cartTotalINR, user.ID)
	if err != nil {
		logErrorWithTrace("coupon validation error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to validate coupon"})
		return
	}

	if resp.Valid {
		writeJSON(w, http.StatusOK, resp)
	} else {
		writeJSON(w, http.StatusBadRequest, resp)
	}
}

// ─── Core Validation Logic ───────────────────────────────────────────────────

// validateAndCalcDiscount validates a coupon code against the given cart total
// and user, returning the discount amount and final total.
func validateAndCalcDiscount(ctx context.Context, repo *productRepository, code string, cartTotalINR float64, userID int64) (applyCouponResponse, error) {
	coupon, found, err := getCouponByCode(ctx, repo, code)
	if err != nil {
		return applyCouponResponse{}, err
	}
	if !found {
		return applyCouponResponse{Valid: false, Message: "Invalid coupon code"}, nil
	}
	if !coupon.IsActive {
		return applyCouponResponse{Valid: false, Message: "This coupon is no longer active"}, nil
	}

	// Check min order amount
	if cartTotalINR < coupon.MinOrderAmount {
		return applyCouponResponse{
			Valid:   false,
			Message: "Minimum order amount of ₹" + formatINR(coupon.MinOrderAmount) + " required",
		}, nil
	}

	// Check max order amount
	if coupon.MaxOrderAmount != nil && cartTotalINR > *coupon.MaxOrderAmount {
		return applyCouponResponse{
			Valid:   false,
			Message: "Coupon not applicable for orders above ₹" + formatINR(*coupon.MaxOrderAmount),
		}, nil
	}

	// Check global usage limit
	if coupon.MaxUses > 0 && coupon.TimesUsed >= coupon.MaxUses {
		return applyCouponResponse{Valid: false, Message: "This coupon has reached its usage limit"}, nil
	}

	// Check per-user usage limit
	if coupon.MaxUsesPerUser > 0 {
		userUses, err := countCouponUsagesByUser(ctx, repo, coupon.ID, userID)
		if err != nil {
			return applyCouponResponse{}, err
		}
		if userUses >= coupon.MaxUsesPerUser {
			return applyCouponResponse{Valid: false, Message: "You have already used this coupon the maximum number of times"}, nil
		}
	}

	// Calculate discount
	var discount float64
	switch coupon.DiscountType {
	case "flat":
		discount = coupon.DiscountValue
	case "percentage":
		discount = cartTotalINR * coupon.DiscountValue / 100.0
		if coupon.MaxDiscountCap != nil && discount > *coupon.MaxDiscountCap {
			discount = *coupon.MaxDiscountCap
		}
	}

	// Ensure discount doesn't exceed cart total
	discount = math.Round(discount)
	if discount >= cartTotalINR {
		discount = cartTotalINR - 1 // never make order completely free
	}
	if discount < 0 {
		discount = 0
	}

	finalTotal := cartTotalINR - discount

	return applyCouponResponse{
		Valid:          true,
		CouponID:       coupon.ID,
		Code:           coupon.Code,
		DiscountAmount: discount,
		FinalTotal:     finalTotal,
		Message:        "Coupon applied successfully",
	}, nil
}

// validateCouponInTx re-validates a coupon inside a transaction (for
// concurrency safety during order creation). Returns couponID and
// discountPaisa, or an error message.
func validateCouponInTx(ctx context.Context, tx *sql.Tx, dialect string, code string, cartTotalINR float64, userID int64) (couponID int64, discountPaisa int64, errMsg string, err error) {
	row := tx.QueryRowContext(ctx, rebindQuery(`
		SELECT id, code, discount_type, discount_value, max_discount_cap, min_order_amount, max_order_amount,
		       max_uses, max_uses_per_user, times_used, is_active
		FROM coupons WHERE code = ?`+forUpdateClause(dialect), dialect), code)

	var c Coupon
	var maxCap, maxOrd sql.NullFloat64
	var activeInt int
	if err := row.Scan(&c.ID, &c.Code, &c.DiscountType, &c.DiscountValue, &maxCap, &c.MinOrderAmount, &maxOrd,
		&c.MaxUses, &c.MaxUsesPerUser, &c.TimesUsed, &activeInt); err != nil {
		if err == sql.ErrNoRows {
			return 0, 0, "Invalid coupon code", nil
		}
		return 0, 0, "", err
	}
	c.IsActive = activeInt != 0
	if maxCap.Valid {
		c.MaxDiscountCap = &maxCap.Float64
	}
	if maxOrd.Valid {
		c.MaxOrderAmount = &maxOrd.Float64
	}

	if !c.IsActive {
		return 0, 0, "This coupon is no longer active", nil
	}
	if cartTotalINR < c.MinOrderAmount {
		return 0, 0, "Minimum order amount of ₹" + formatINR(c.MinOrderAmount) + " required", nil
	}
	if c.MaxOrderAmount != nil && cartTotalINR > *c.MaxOrderAmount {
		return 0, 0, "Coupon not applicable for orders above ₹" + formatINR(*c.MaxOrderAmount), nil
	}
	if c.MaxUses > 0 && c.TimesUsed >= c.MaxUses {
		return 0, 0, "This coupon has reached its usage limit", nil
	}

	// Per-user usage check inside transaction
	if c.MaxUsesPerUser > 0 {
		var userUses int
		err := tx.QueryRowContext(ctx, rebindQuery(`
			SELECT COUNT(*) FROM coupon_usages WHERE coupon_id = ? AND user_id = ?`, dialect), c.ID, userID).Scan(&userUses)
		if err != nil {
			return 0, 0, "", err
		}
		if userUses >= c.MaxUsesPerUser {
			return 0, 0, "You have already used this coupon the maximum number of times", nil
		}
	}

	// Calculate discount
	var discount float64
	switch c.DiscountType {
	case "flat":
		discount = c.DiscountValue
	case "percentage":
		discount = cartTotalINR * c.DiscountValue / 100.0
		if c.MaxDiscountCap != nil && discount > *c.MaxDiscountCap {
			discount = *c.MaxDiscountCap
		}
	}

	discount = math.Round(discount)
	if discount >= cartTotalINR {
		discount = cartTotalINR - 1
	}
	if discount < 0 {
		discount = 0
	}

	discountPaisa = int64(discount * 100)
	return c.ID, discountPaisa, "", nil
}

// ─── DB Helpers ──────────────────────────────────────────────────────────────

func getCouponByID(ctx context.Context, repo *productRepository, id int64) (Coupon, bool, error) {
	row := repo.queryRow(ctx, `
		SELECT id, code, discount_type, discount_value, max_discount_cap, min_order_amount, max_order_amount,
		       max_uses, max_uses_per_user, times_used, is_active, created_at
		FROM coupons WHERE id = ?`, id)
	return scanSingleCoupon(row)
}

func getCouponByCode(ctx context.Context, repo *productRepository, code string) (Coupon, bool, error) {
	row := repo.queryRow(ctx, `
		SELECT id, code, discount_type, discount_value, max_discount_cap, min_order_amount, max_order_amount,
		       max_uses, max_uses_per_user, times_used, is_active, created_at
		FROM coupons WHERE code = ?`, code)
	return scanSingleCoupon(row)
}

func scanSingleCoupon(row *sql.Row) (Coupon, bool, error) {
	var c Coupon
	var maxCap, maxOrd sql.NullFloat64
	var activeInt int
	err := row.Scan(&c.ID, &c.Code, &c.DiscountType, &c.DiscountValue, &maxCap, &c.MinOrderAmount, &maxOrd,
		&c.MaxUses, &c.MaxUsesPerUser, &c.TimesUsed, &activeInt, &c.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return Coupon{}, false, nil
		}
		return Coupon{}, false, err
	}
	c.IsActive = activeInt != 0
	if maxCap.Valid {
		c.MaxDiscountCap = &maxCap.Float64
	}
	if maxOrd.Valid {
		c.MaxOrderAmount = &maxOrd.Float64
	}
	return c, true, nil
}

func scanCouponRow(rows *sql.Rows) (Coupon, error) {
	var c Coupon
	var maxCap, maxOrd sql.NullFloat64
	var activeInt int
	err := rows.Scan(&c.ID, &c.Code, &c.DiscountType, &c.DiscountValue, &maxCap, &c.MinOrderAmount, &maxOrd,
		&c.MaxUses, &c.MaxUsesPerUser, &c.TimesUsed, &activeInt, &c.CreatedAt)
	if err != nil {
		return Coupon{}, err
	}
	c.IsActive = activeInt != 0
	if maxCap.Valid {
		c.MaxDiscountCap = &maxCap.Float64
	}
	if maxOrd.Valid {
		c.MaxOrderAmount = &maxOrd.Float64
	}
	return c, nil
}

func countCouponUsagesByUser(ctx context.Context, repo *productRepository, couponID, userID int64) (int, error) {
	var count int
	err := repo.queryRow(ctx, `SELECT COUNT(*) FROM coupon_usages WHERE coupon_id = ? AND user_id = ?`, couponID, userID).Scan(&count)
	return count, err
}

func formatINR(amount float64) string {
	if amount == math.Trunc(amount) {
		return strconv.FormatInt(int64(amount), 10)
	}
	return strconv.FormatFloat(amount, 'f', 2, 64)
}
