package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type OrderItemOut struct {
	Product  string  `json:"product"`
	Size     string  `json:"size"`
	Quantity int     `json:"quantity"`
	Price    int64   `json:"price,omitempty"`
	Image    *string `json:"image"`
}

type OrderOut struct {
	ID              int64          `json:"id"`
	User            string         `json:"user,omitempty"`
	Phone           string         `json:"phone,omitempty"`
	TotalAmount     int64          `json:"total_amount"`
	DeliveryStatus  string         `json:"delivery_status"`
	ConsignNumber   string         `json:"consignment_number,omitempty"`
	RazorpayOrderID string         `json:"razorpay_order_id,omitempty"`
	RazorpayPayment string         `json:"razorpay_payment_id,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
	Address         map[string]any `json:"address"`
	Items           []OrderItemOut `json:"items"`
}

func registerOrderRoutes(mux *http.ServeMux) {
	mux.Handle("/api/create-order/", ClerkMiddleware(http.HandlerFunc(createOrderHandler)))
	mux.Handle("/api/create-order", ClerkMiddleware(http.HandlerFunc(createOrderHandler)))
	mux.Handle("/api/verify-payment/", ClerkMiddleware(http.HandlerFunc(verifyPaymentHandler)))
	mux.Handle("/api/verify-payment", ClerkMiddleware(http.HandlerFunc(verifyPaymentHandler)))
	mux.Handle("/api/order-list/", ClerkMiddleware(http.HandlerFunc(orderListHandler)))
	mux.Handle("/api/order-list", ClerkMiddleware(http.HandlerFunc(orderListHandler)))
	mux.Handle("/api/all-orders/", ClerkMiddleware(http.HandlerFunc(allOrdersHandler)))
	mux.Handle("/api/all-orders", ClerkMiddleware(http.HandlerFunc(allOrdersHandler)))

	// Backward-compatible aliases without /api prefix.
	mux.Handle("/create-order/", ClerkMiddleware(http.HandlerFunc(createOrderHandler)))
	mux.Handle("/create-order", ClerkMiddleware(http.HandlerFunc(createOrderHandler)))
	mux.Handle("/verify-payment/", ClerkMiddleware(http.HandlerFunc(verifyPaymentHandler)))
	mux.Handle("/verify-payment", ClerkMiddleware(http.HandlerFunc(verifyPaymentHandler)))
	mux.Handle("/order-list/", ClerkMiddleware(http.HandlerFunc(orderListHandler)))
	mux.Handle("/order-list", ClerkMiddleware(http.HandlerFunc(orderListHandler)))
	mux.Handle("/all-orders/", ClerkMiddleware(http.HandlerFunc(allOrdersHandler)))
	mux.Handle("/all-orders", ClerkMiddleware(http.HandlerFunc(allOrdersHandler)))
}

func createOrderHandler(w http.ResponseWriter, r *http.Request) {
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

	address, found, err := getAddressByUserID(r.Context(), user.ID)
	if err != nil {
		logErrorWithTrace("failed to fetch address", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "failed to fetch address"})
		return
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "Address not found for user."})
		return
	}

	amount, err := parseAmountField(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid amount"})
		return
	}

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
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Cart is empty"})
		return
	}

	totalAmountINR := calcCartTotalINR(items)
	if amount != int64(totalAmountINR) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid amount"})
		return
	}

	for _, it := range items {
		stockQty, hasStock, err := stockForProductSize(r.Context(), repo, it.ProductID, it.Size)
		if err != nil {
			logErrorWithTrace("failed to fetch stock", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to fetch stock"})
			return
		}
		if !hasStock {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("Stock entry not found for %s (%s)", it.ProductName, it.Size)})
			return
		}
		if stockQty < it.Quantity {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("Insufficient stock for %s (%s)", it.ProductName, it.Size)})
			return
		}
	}

	orderResp, err := createRazorpayOrder(amount * 100)
	if err != nil {
		logErrorWithTrace("failed to create razorpay order", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create payment order"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"order_id":     orderResp.ID,
		"razorpay_key": razorpayKeyID(),
		"amount":       orderResp.Amount,
		"name":         strings.TrimSpace(address.FirstName + " " + address.LastName),
		"email":        user.Email,
		"phone":        address.PhoneNumber,
	})
}

func verifyPaymentHandler(w http.ResponseWriter, r *http.Request) {
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

	payload, err := parsePaymentVerifyPayload(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid payload"})
		return
	}

	if !verifyRazorpaySignature(payload.OrderID, payload.PaymentID, payload.Signature) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid signature"})
		return
	}

	address, found, err := getAddressByUserID(r.Context(), user.ID)
	if err != nil {
		logErrorWithTrace("failed to fetch address", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "failed to fetch address"})
		return
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "Address not found for user."})
		return
	}

	cartID, err := getOrCreateCartID(r.Context(), repo, user.ID)
	if err != nil {
		logErrorWithTrace("failed to get cart", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to fetch cart"})
		return
	}

	tx, err := repo.db.BeginTx(r.Context(), nil)
	if err != nil {
		logErrorWithTrace("failed to start transaction", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create order"})
		return
	}
	defer tx.Rollback()

	items, err := getCartItemsForOrderTx(r.Context(), tx, repo.dialect, cartID)
	if err != nil {
		logErrorWithTrace("failed to fetch cart items", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to fetch cart"})
		return
	}
	if len(items) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Cart is empty"})
		return
	}

	totalPaisa := int64(calcCartTotalINR(items) * 100)

	stockRows, err := tx.QueryContext(r.Context(), rebindQuery(`
		SELECT product_id, size, quantity
		FROM product_stock
		WHERE (product_id, size) IN (`+pairPlaceholders(len(items))+`)`+forUpdateClause(repo.dialect), repo.dialect), pairArgs(items)...)
	if err != nil {
		logErrorWithTrace("failed to lock stock", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to verify stock"})
		return
	}
	stockMap := map[string]int{}
	for stockRows.Next() {
		var pid int64
		var size string
		var qty int
		if err := stockRows.Scan(&pid, &size, &qty); err != nil {
			_ = stockRows.Close()
			logErrorWithTrace("failed to scan stock", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to verify stock"})
			return
		}
		stockMap[fmt.Sprintf("%d|%s", pid, size)] = qty
	}
	_ = stockRows.Close()

	for _, it := range items {
		key := fmt.Sprintf("%d|%s", it.ProductID, it.Size)
		qty, ok := stockMap[key]
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("Stock entry not found for %s (%s)", it.ProductName, it.Size)})
			return
		}
		if qty < it.Quantity {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("Insufficient stock for %s (%s)", it.ProductName, it.Size)})
			return
		}
	}

	var orderID int64
	insertOrder := `
		INSERT INTO orders(user_id, address_id, razorpay_order_id, razorpay_payment_id, razorpay_signature, total_amount, delivery_status)
		VALUES(?, ?, ?, ?, ?, ?, 'pending')`
	if repo.dialect == "postgres" {
		if err := tx.QueryRowContext(r.Context(), rebindQuery(insertOrder+` RETURNING id`, repo.dialect), user.ID, address.ID, payload.OrderID, payload.PaymentID, payload.Signature, totalPaisa).Scan(&orderID); err != nil {
			logErrorWithTrace("failed to create order", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create order"})
			return
		}
	} else {
		res, err := tx.ExecContext(r.Context(), rebindQuery(insertOrder, repo.dialect), user.ID, address.ID, payload.OrderID, payload.PaymentID, payload.Signature, totalPaisa)
		if err != nil {
			logErrorWithTrace("failed to create order", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create order"})
			return
		}
		orderID, _ = res.LastInsertId()
	}

	for _, it := range items {
		pricePaisa := int64(math.Round(it.Price * 100))
		if _, err := tx.ExecContext(r.Context(), rebindQuery(`
			INSERT INTO order_items(order_id, product_id, size, quantity, price)
			VALUES(?, ?, ?, ?, ?)`, repo.dialect), orderID, it.ProductID, it.Size, it.Quantity, pricePaisa); err != nil {
			logErrorWithTrace("failed to create order item", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create order item"})
			return
		}

		if _, err := tx.ExecContext(r.Context(), rebindQuery(`
			UPDATE product_stock SET quantity = quantity - ?
			WHERE product_id = ? AND size = ?`, repo.dialect), it.Quantity, it.ProductID, it.Size); err != nil {
			logErrorWithTrace("failed to update stock", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to update stock"})
			return
		}
	}

	if _, err := tx.ExecContext(r.Context(), rebindQuery(`DELETE FROM cart_items WHERE cart_id = ?`, repo.dialect), cartID); err != nil {
		logErrorWithTrace("failed to clear cart", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to clear cart"})
		return
	}

	if err := tx.Commit(); err != nil {
		logErrorWithTrace("failed to commit order", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create order"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "Payment verified, order created"})
}

func orderListHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
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

	orders, err := listOrders(r.Context(), repo, &user.ID)
	if err != nil {
		logErrorWithTrace("failed to list orders", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "failed to fetch orders"})
		return
	}
	writeJSON(w, http.StatusOK, orders)
}

func allOrdersHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := authenticatedAppUser(w, r)
	if !ok {
		return
	}
	if user.Role != "manager" {
		writeJSON(w, http.StatusForbidden, map[string]string{"detail": "manager access required"})
		return
	}

	repo, err := getProductRepository()
	if err != nil {
		logErrorWithTrace("database initialization failed", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "database initialization failed"})
		return
	}

	path := strings.TrimSuffix(r.URL.Path, "/")
	base := "/api/all-orders"
	if strings.HasPrefix(path, "/all-orders") {
		base = "/all-orders"
	}
	if !strings.HasPrefix(path, base) {
		http.NotFound(w, r)
		return
	}

	if r.Method == http.MethodGet && (path == base) {
		orders, err := listOrders(r.Context(), repo, nil)
		if err != nil {
			logErrorWithTrace("failed to list all orders", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "failed to fetch orders"})
			return
		}
		writeJSON(w, http.StatusOK, orders)
		return
	}

	if r.Method == http.MethodPut && path != base {
		rawID := strings.TrimPrefix(path, base+"/")
		orderID, err := strconv.ParseInt(rawID, 10, 64)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "Order not found"})
			return
		}
		handleUpdateOrderStatus(w, r, repo, orderID)
		return
	}

	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func handleUpdateOrderStatus(w http.ResponseWriter, r *http.Request, repo *productRepository, orderID int64) {
	payload, err := parseStatusUpdatePayload(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid payload"})
		return
	}
	if !isValidDeliveryStatus(payload.DeliveryStatus) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid delivery status"})
		return
	}

	res, err := repo.exec(r.Context(), `
		UPDATE orders
		SET delivery_status = ?, consignment_number = ?
		WHERE id = ?`, payload.DeliveryStatus, nullableString(payload.ConsignmentNumber), orderID)
	if err != nil {
		logErrorWithTrace("failed to update order status", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to update order"})
		return
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Order not found"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "Delivery status updated successfully"})
}

type orderCartItem struct {
	ID          int64
	ProductID   int64
	ProductName string
	Size        string
	Quantity    int
	Price       float64
}

func getCartItemsForOrder(ctx context.Context, repo *productRepository, cartID int64) ([]orderCartItem, error) {
	return getCartItemsForOrderTx(ctx, nil, repo.dialect, cartID)
}

func getCartItemsForOrderTx(ctx context.Context, tx *sql.Tx, dialect string, cartID int64) ([]orderCartItem, error) {
	query := rebindQuery(`
		SELECT ci.id, ci.product_id, p.name, ci.size, ci.quantity, p.price
		FROM cart_items ci
		JOIN products p ON p.id = ci.product_id
		WHERE ci.cart_id = ?
		ORDER BY ci.id ASC`, dialect)

	var (
		rows *sql.Rows
		err  error
	)
	if tx != nil {
		rows, err = tx.QueryContext(ctx, query, cartID)
	} else {
		repo, gerr := getProductRepository()
		if gerr != nil {
			return nil, gerr
		}
		rows, err = repo.db.QueryContext(ctx, query, cartID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]orderCartItem, 0)
	for rows.Next() {
		var it orderCartItem
		if err := rows.Scan(&it.ID, &it.ProductID, &it.ProductName, &it.Size, &it.Quantity, &it.Price); err != nil {
			return nil, err
		}
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

func calcCartTotalINR(items []orderCartItem) int {
	total := 0.0
	for _, it := range items {
		total += it.Price * float64(it.Quantity)
	}
	return int(math.Round(total))
}

type razorpayOrderResponse struct {
	ID     string `json:"id"`
	Amount int64  `json:"amount"`
}

func createRazorpayOrder(amountPaisa int64) (*razorpayOrderResponse, error) {
	key := razorpayKeyID()
	secret := razorpayKeySecret()
	if key == "" || secret == "" {
		return nil, errors.New("razorpay credentials not configured")
	}

	body := map[string]any{"amount": amountPaisa, "currency": "INR", "payment_capture": 1}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, "https://api.razorpay.com/v1/orders", strings.NewReader(string(b)))
	req.SetBasicAuth(key, secret)
	req.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("razorpay returned status %d", resp.StatusCode)
	}

	var out razorpayOrderResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func razorpayKeyID() string {
	if v := strings.TrimSpace(os.Getenv("RAZORPAY_KEY_ID")); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv("RAZOR_PAY_API_KEY"))
}

func razorpayKeySecret() string {
	if v := strings.TrimSpace(os.Getenv("RAZORPAY_KEY_SECRET")); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv("RAZOR_PAY_API_SECRET"))
}

func verifyRazorpaySignature(orderID, paymentID, signature string) bool {
	secret := razorpayKeySecret()
	if secret == "" {
		return false
	}
	h := hmac.New(sha256.New, []byte(secret))
	_, _ = h.Write([]byte(orderID + "|" + paymentID))
	generated := hex.EncodeToString(h.Sum(nil))
	return hmac.Equal([]byte(generated), []byte(signature))
}

type paymentVerifyPayload struct {
	OrderID   string
	PaymentID string
	Signature string
}

func parsePaymentVerifyPayload(r *http.Request) (paymentVerifyPayload, error) {
	m, err := parseAnyBody(r)
	if err != nil {
		return paymentVerifyPayload{}, err
	}
	return paymentVerifyPayload{
		OrderID:   strings.TrimSpace(m["razorpay_order_id"]),
		PaymentID: strings.TrimSpace(m["razorpay_payment_id"]),
		Signature: strings.TrimSpace(m["razorpay_signature"]),
	}, nil
}

type statusUpdatePayload struct {
	DeliveryStatus    string
	ConsignmentNumber string
}

func parseStatusUpdatePayload(r *http.Request) (statusUpdatePayload, error) {
	m, err := parseAnyBody(r)
	if err != nil {
		return statusUpdatePayload{}, err
	}
	return statusUpdatePayload{
		DeliveryStatus:    strings.TrimSpace(m["delivery_status"]),
		ConsignmentNumber: strings.TrimSpace(m["consignment_number"]),
	}, nil
}

func parseAmountField(r *http.Request) (int64, error) {
	m, err := parseAnyBody(r)
	if err != nil {
		return 0, err
	}
	raw := strings.TrimSpace(m["amount"])
	if raw == "" {
		return 0, errors.New("missing amount")
	}
	if i, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return i, nil
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, err
	}
	return int64(math.Round(f)), nil
}

func parseAnyBody(r *http.Request) (map[string]string, error) {
	ctype := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
	out := map[string]string{}

	if strings.Contains(ctype, "application/json") {
		var m map[string]any
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			return nil, err
		}
		for k, v := range m {
			out[k] = fmt.Sprintf("%v", v)
		}
		return out, nil
	}

	if strings.Contains(ctype, "multipart/form-data") {
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			return nil, err
		}
	} else {
		if err := r.ParseForm(); err != nil {
			return nil, err
		}
	}

	for k := range r.Form {
		out[k] = r.FormValue(k)
	}
	return out, nil
}

func pairPlaceholders(n int) string {
	parts := make([]string, 0, n)
	for i := 0; i < n; i++ {
		parts = append(parts, "(?, ?)")
	}
	return strings.Join(parts, ",")
}

func pairArgs(items []orderCartItem) []any {
	args := make([]any, 0, len(items)*2)
	for _, it := range items {
		args = append(args, it.ProductID, it.Size)
	}
	return args
}

func forUpdateClause(dialect string) string {
	if dialect == "postgres" {
		return " FOR UPDATE"
	}
	return ""
}

func nullableString(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

func isValidDeliveryStatus(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "pending", "shipped", "delivered", "cancelled":
		return true
	default:
		return false
	}
}

func listOrders(ctx context.Context, repo *productRepository, userID *int64) ([]OrderOut, error) {
	query := `
		SELECT o.id, o.user_id, COALESCE(u.email, ''), COALESCE(a.first_name, ''), COALESCE(a.last_name, ''), COALESCE(a.address_line1, ''),
		       COALESCE(a.street, ''), COALESCE(a.city, ''), COALESCE(a.state, ''), COALESCE(a.postal_code, ''), COALESCE(a.phone_number, ''),
		       COALESCE(o.total_amount, 0), COALESCE(o.delivery_status, 'pending'), COALESCE(o.consignment_number, ''),
		       COALESCE(o.razorpay_order_id, ''), COALESCE(o.razorpay_payment_id, ''), o.created_at
		FROM orders o
		LEFT JOIN custom_users u ON u.id = o.user_id
		LEFT JOIN addresses a ON a.id = o.address_id`
	args := []any{}
	if userID != nil {
		query += ` WHERE o.user_id = ?`
		args = append(args, *userID)
	}
	query += ` ORDER BY o.created_at DESC`

	rows, err := repo.query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	orders := make([]OrderOut, 0)
	orderIDs := make([]int64, 0)
	orderMap := map[int64]*OrderOut{}

	for rows.Next() {
		var o OrderOut
		var uid int64
		var first, last, line1, street, city, state, postal, phone string
		if err := rows.Scan(&o.ID, &uid, &o.User, &first, &last, &line1, &street, &city, &state, &postal, &phone, &o.TotalAmount, &o.DeliveryStatus, &o.ConsignNumber, &o.RazorpayOrderID, &o.RazorpayPayment, &o.CreatedAt); err != nil {
			return nil, err
		}
		o.Phone = phone
		o.Address = map[string]any{
			"first_name":    first,
			"last_name":     last,
			"address_line1": line1,
			"street":        street,
			"city":          city,
			"state":         state,
			"postal_code":   postal,
			"phone":         phone,
		}
		o.Items = []OrderItemOut{}
		orders = append(orders, o)
		orderIDs = append(orderIDs, o.ID)
		orderMap[o.ID] = &orders[len(orders)-1]
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(orderIDs) == 0 {
		return orders, nil
	}

	itemQ := fmt.Sprintf(`
		SELECT oi.order_id, COALESCE(p.name, ''), oi.size, COALESCE(oi.quantity, 0), COALESCE(oi.price, 0),
		       (SELECT image FROM product_images pi WHERE pi.product_id = oi.product_id ORDER BY pi.id ASC LIMIT 1) as image
		FROM order_items oi
		LEFT JOIN products p ON p.id = oi.product_id
		WHERE oi.order_id IN (%s)
		ORDER BY oi.id ASC`, placeholders(len(orderIDs)))

	itemArgs := make([]any, 0, len(orderIDs))
	for _, id := range orderIDs {
		itemArgs = append(itemArgs, id)
	}

	itemRows, err := repo.query(ctx, itemQ, itemArgs...)
	if err != nil {
		return nil, err
	}
	defer itemRows.Close()

	for itemRows.Next() {
		var orderID int64
		var it OrderItemOut
		var image sql.NullString
		if err := itemRows.Scan(&orderID, &it.Product, &it.Size, &it.Quantity, &it.Price, &image); err != nil {
			return nil, err
		}
		if image.Valid && strings.TrimSpace(image.String) != "" {
			u := image.String
			it.Image = &u
		}
		if ref, ok := orderMap[orderID]; ok {
			ref.Items = append(ref.Items, it)
		}
	}
	if err := itemRows.Err(); err != nil {
		return nil, err
	}

	return orders, nil
}
