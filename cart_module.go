package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
)

type CartItemResponse struct {
	ID          int64  `json:"id"`
	ProductID   int64  `json:"product_id"`
	ProductName string `json:"product_name"`
	Size        string `json:"size"`
	Quantity    int    `json:"quantity"`
}

type CartResponse struct {
	ID      int64              `json:"id"`
	User    int64              `json:"user"`
	Items   []CartItemResponse `json:"items"`
	Warning string             `json:"warning,omitempty"`
	Removed string             `json:"removed,omitempty"`
}

type cartItemInput struct {
	ItemID    int64  `json:"item_id"`
	ProductID int64  `json:"product_id"`
	Size      string `json:"size"`
	Quantity  int    `json:"quantity"`
}

func registerCartRoutes(mux *http.ServeMux) {
	mux.Handle("/api/cart", ClerkMiddleware(http.HandlerFunc(cartHandler)))
	mux.Handle("/api/cart/", ClerkMiddleware(http.HandlerFunc(cartHandler)))
	mux.Handle("/cart", ClerkMiddleware(http.HandlerFunc(cartHandler)))
	mux.Handle("/cart/", ClerkMiddleware(http.HandlerFunc(cartHandler)))
}

func cartHandler(w http.ResponseWriter, r *http.Request) {
	if !isCartPath(r.URL.Path) {
		http.NotFound(w, r)
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

	cartID, err := getOrCreateCartID(r.Context(), repo, user.ID)
	if err != nil {
		logErrorWithTrace("failed to get or create cart", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "failed to get cart"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		handleGetCart(w, r, repo, cartID, user.ID)
	case http.MethodPost:
		handlePostCartItem(w, r, repo, cartID)
	case http.MethodPut:
		handlePutCartItem(w, r, repo, cartID)
	case http.MethodDelete:
		handleDeleteCartItem(w, r, repo, cartID)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleGetCart(w http.ResponseWriter, r *http.Request, repo *productRepository, cartID, userID int64) {
	removedCount, err := removeHiddenProductItems(r.Context(), repo, cartID)
	if err != nil {
		if isRequestCanceled(err) {
			log.Printf("cart get request canceled by client: %v", err)
			return
		}
		logErrorWithTrace("failed to clean hidden cart items", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "failed to fetch cart"})
		return
	}

	updated, err := reconcileCartQuantities(r.Context(), repo, cartID)
	if err != nil {
		if isRequestCanceled(err) {
			log.Printf("cart reconcile request canceled by client: %v", err)
			return
		}
		logErrorWithTrace("failed to reconcile cart quantities", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "failed to fetch cart"})
		return
	}

	items, err := listCartItems(r.Context(), repo, cartID)
	if err != nil {
		if isRequestCanceled(err) {
			log.Printf("cart list request canceled by client: %v", err)
			return
		}
		logErrorWithTrace("failed to list cart items", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "failed to fetch cart"})
		return
	}

	resp := CartResponse{ID: cartID, User: userID, Items: items}
	if updated {
		resp.Warning = "Some cart items were updated due to limited stock."
	}
	if removedCount > 0 {
		resp.Removed = "Some items were removed because the product is no longer available."
	}

	writeJSON(w, http.StatusOK, resp)
}

func handlePostCartItem(w http.ResponseWriter, r *http.Request, repo *productRepository, cartID int64) {
	in, err := parseCartItemInput(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON body."})
		return
	}

	in.Size = strings.TrimSpace(in.Size)
	if in.Quantity == 0 {
		in.Quantity = 1
	}
	if in.ProductID == 0 || in.Size == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "product_id and size are required."})
		return
	}
	if in.Quantity < 1 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "quantity must be at least 1."})
		return
	}

	productName, exists, err := productExistsByID(r.Context(), repo, in.ProductID)
	if err != nil {
		logErrorWithTrace("failed to fetch product", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to fetch product."})
		return
	}
	if !exists {
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "Product not found."})
		return
	}

	stockQty, hasStock, err := stockForProductSize(r.Context(), repo, in.ProductID, in.Size)
	if err != nil {
		logErrorWithTrace("failed to fetch stock", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to fetch stock."})
		return
	}
	if !hasStock || in.Quantity > stockQty {
		available := 0
		if hasStock {
			available = stockQty
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("Only %d items available in size %s.", available, in.Size)})
		return
	}

	existing, found, err := findCartItem(r.Context(), repo, cartID, in.ProductID, in.Size)
	if err != nil {
		logErrorWithTrace("failed to fetch cart item", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to update cart."})
		return
	}
	if found {
		total := existing.Quantity + in.Quantity
		if total > stockQty {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("Only %d items available in total for size %s.", stockQty, in.Size)})
			return
		}

		if err := updateCartItemQuantityByID(r.Context(), repo, existing.ID, total); err != nil {
			logErrorWithTrace("failed to update existing cart item", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to update cart item."})
			return
		}
		existing.Quantity = total
		existing.ProductName = productName
		writeJSON(w, http.StatusOK, existing)
		return
	}

	itemID, err := insertCartItem(r.Context(), repo, cartID, in.ProductID, in.Size, in.Quantity)
	if err != nil {
		logErrorWithTrace("failed to insert cart item", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to add cart item."})
		return
	}

	writeJSON(w, http.StatusCreated, CartItemResponse{
		ID:          itemID,
		ProductID:   in.ProductID,
		ProductName: productName,
		Size:        in.Size,
		Quantity:    in.Quantity,
	})
}

func handlePutCartItem(w http.ResponseWriter, r *http.Request, repo *productRepository, cartID int64) {
	in, err := parseCartItemInput(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON body."})
		return
	}

	in.Size = strings.TrimSpace(in.Size)
	if in.ProductID == 0 || in.Size == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "product_id and size are required."})
		return
	}
	if in.Quantity < 1 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "quantity must be at least 1."})
		return
	}

	item, found, err := findCartItem(r.Context(), repo, cartID, in.ProductID, in.Size)
	if err != nil {
		logErrorWithTrace("failed to fetch cart item", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to update cart item."})
		return
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "Cart item not found."})
		return
	}

	stockQty, hasStock, err := stockForProductSize(r.Context(), repo, item.ProductID, item.Size)
	if err != nil {
		logErrorWithTrace("failed to fetch stock", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to fetch stock."})
		return
	}
	if !hasStock || in.Quantity > stockQty {
		available := 0
		if hasStock {
			available = stockQty
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("Only %d items available in size %s.", available, item.Size)})
		return
	}

	if err := updateCartItemQuantityByID(r.Context(), repo, item.ID, in.Quantity); err != nil {
		logErrorWithTrace("failed to update cart item", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to update cart item."})
		return
	}

	item.Quantity = in.Quantity
	writeJSON(w, http.StatusOK, item)
}

func handleDeleteCartItem(w http.ResponseWriter, r *http.Request, repo *productRepository, cartID int64) {
	in, err := parseCartItemInput(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON body."})
		return
	}
	if in.ItemID == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "item_id is required to delete a cart item."})
		return
	}

	removed, err := deleteCartItemByID(r.Context(), repo, cartID, in.ItemID)
	if err != nil {
		logErrorWithTrace("failed to delete cart item", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to delete cart item."})
		return
	}
	if !removed {
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "Cart item not found."})
		return
	}

	writeJSON(w, http.StatusNoContent, map[string]string{"message": "Item removed from cart."})
}

func authenticatedAppUser(w http.ResponseWriter, r *http.Request) (CustomUser, bool) {
	clerkUser, ok := FromContext(r.Context())
	if !ok || clerkUser == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"detail": "authentication required"})
		return CustomUser{}, false
	}

	user, found, err := getCustomUserByClerkID(r.Context(), clerkUser.ID)
	if err != nil {
		logErrorWithTrace("failed to fetch user", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "failed to fetch user"})
		return CustomUser{}, false
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "User not found."})
		return CustomUser{}, false
	}
	return user, true
}

func getOrCreateCartID(ctx context.Context, repo *productRepository, userID int64) (int64, error) {
	if _, err := repo.exec(ctx, `
		INSERT INTO carts(user_id)
		VALUES(?)
		ON CONFLICT(user_id) DO NOTHING`, userID); err != nil {
		return 0, err
	}

	var cartID int64
	if err := repo.queryRow(ctx, `SELECT id FROM carts WHERE user_id = ?`, userID).Scan(&cartID); err != nil {
		return 0, err
	}
	return cartID, nil
}

func removeHiddenProductItems(ctx context.Context, repo *productRepository, cartID int64) (int64, error) {
	res, err := repo.exec(ctx, `
		DELETE FROM cart_items
		WHERE cart_id = ?
		AND product_id IN (
			SELECT id FROM products WHERE show_flag = 0
		)`, cartID)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return n, nil
}

func reconcileCartQuantities(ctx context.Context, repo *productRepository, cartID int64) (bool, error) {
	rows, err := repo.query(ctx, `
		SELECT ci.id, ci.quantity, COALESCE(ps.quantity, 0) as available
		FROM cart_items ci
		LEFT JOIN product_stock ps ON ps.product_id = ci.product_id AND ps.size = ci.size
		WHERE ci.cart_id = ?`, cartID)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	updated := false
	for rows.Next() {
		var itemID int64
		var qty int
		var available int
		if err := rows.Scan(&itemID, &qty, &available); err != nil {
			return false, err
		}
		if qty > available {
			if err := updateCartItemQuantityByID(ctx, repo, itemID, available); err != nil {
				return false, err
			}
			updated = true
		}
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	return updated, nil
}

func listCartItems(ctx context.Context, repo *productRepository, cartID int64) ([]CartItemResponse, error) {
	rows, err := repo.query(ctx, `
		SELECT ci.id, ci.product_id, p.name, ci.size, ci.quantity
		FROM cart_items ci
		JOIN products p ON p.id = ci.product_id
		WHERE ci.cart_id = ?
		ORDER BY ci.id ASC`, cartID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]CartItemResponse, 0)
	for rows.Next() {
		var item CartItemResponse
		if err := rows.Scan(&item.ID, &item.ProductID, &item.ProductName, &item.Size, &item.Quantity); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

func productExistsByID(ctx context.Context, repo *productRepository, productID int64) (string, bool, error) {
	var name string
	err := repo.queryRow(ctx, `SELECT name FROM products WHERE id = ?`, productID).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return name, true, nil
}

func stockForProductSize(ctx context.Context, repo *productRepository, productID int64, size string) (int, bool, error) {
	var qty int
	err := repo.queryRow(ctx, `
		SELECT quantity
		FROM product_stock
		WHERE product_id = ? AND size = ?`, productID, size).Scan(&qty)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return qty, true, nil
}

func findCartItem(ctx context.Context, repo *productRepository, cartID, productID int64, size string) (CartItemResponse, bool, error) {
	row := repo.queryRow(ctx, `
		SELECT ci.id, ci.product_id, p.name, ci.size, ci.quantity
		FROM cart_items ci
		JOIN products p ON p.id = ci.product_id
		WHERE ci.cart_id = ? AND ci.product_id = ? AND ci.size = ?
		LIMIT 1`, cartID, productID, size)

	var item CartItemResponse
	err := row.Scan(&item.ID, &item.ProductID, &item.ProductName, &item.Size, &item.Quantity)
	if errors.Is(err, sql.ErrNoRows) {
		return CartItemResponse{}, false, nil
	}
	if err != nil {
		return CartItemResponse{}, false, err
	}
	return item, true, nil
}

func updateCartItemQuantityByID(ctx context.Context, repo *productRepository, itemID int64, quantity int) error {
	_, err := repo.exec(ctx, `UPDATE cart_items SET quantity = ? WHERE id = ?`, quantity, itemID)
	return err
}

func insertCartItem(ctx context.Context, repo *productRepository, cartID, productID int64, size string, quantity int) (int64, error) {
	if repo.dialect == "postgres" {
		var itemID int64
		err := repo.queryRow(ctx, `
			INSERT INTO cart_items(cart_id, product_id, size, quantity)
			VALUES(?, ?, ?, ?)
			RETURNING id`, cartID, productID, size, quantity).Scan(&itemID)
		if err != nil {
			return 0, err
		}
		return itemID, nil
	}

	res, err := repo.exec(ctx, `
		INSERT INTO cart_items(cart_id, product_id, size, quantity)
		VALUES(?, ?, ?, ?)`, cartID, productID, size, quantity)
	if err != nil {
		return 0, err
	}
	itemID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	return itemID, nil
}

func deleteCartItemByID(ctx context.Context, repo *productRepository, cartID, itemID int64) (bool, error) {
	res, err := repo.exec(ctx, `DELETE FROM cart_items WHERE id = ? AND cart_id = ?`, itemID, cartID)
	if err != nil {
		return false, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected > 0, nil
}

func isCartPath(path string) bool {
	path = strings.TrimSpace(path)
	for strings.HasSuffix(path, "/") && len(path) > 1 {
		path = strings.TrimSuffix(path, "/")
	}
	return path == "/api/cart" || path == "/cart"
}

func parseCartItemInput(r *http.Request) (cartItemInput, error) {
	ctype := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))

	if strings.Contains(ctype, "application/json") {
		var in cartItemInput
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			return cartItemInput{}, err
		}
		return in, nil
	}

	if strings.Contains(ctype, "multipart/form-data") {
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			return cartItemInput{}, err
		}
	} else {
		if err := r.ParseForm(); err != nil {
			return cartItemInput{}, err
		}
	}

	parseInt64 := func(v string) (int64, error) {
		v = strings.TrimSpace(v)
		if v == "" {
			return 0, nil
		}
		return strconv.ParseInt(v, 10, 64)
	}
	parseInt := func(v string) (int, error) {
		v = strings.TrimSpace(v)
		if v == "" {
			return 0, nil
		}
		return strconv.Atoi(v)
	}

	getFirst := func(keys ...string) string {
		for _, k := range keys {
			if v := strings.TrimSpace(r.FormValue(k)); v != "" {
				return v
			}
		}
		return ""
	}

	productID, err := parseInt64(getFirst("product_id", "productId", "productID"))
	if err != nil {
		return cartItemInput{}, err
	}
	itemID, err := parseInt64(getFirst("item_id", "itemId", "itemID"))
	if err != nil {
		return cartItemInput{}, err
	}
	quantity, err := parseInt(getFirst("quantity", "qty"))
	if err != nil {
		return cartItemInput{}, err
	}
	size := getFirst("size", "Size")

	if productID == 0 || size == "" {
		_ = r.ParseForm()
		log.Printf("cart parser missing required fields; content-type=%q form_keys=%v", ctype, formKeys(r))
	}

	return cartItemInput{
		ItemID:    itemID,
		ProductID: productID,
		Size:      strings.TrimSpace(size),
		Quantity:  quantity,
	}, nil
}

func formKeys(r *http.Request) []string {
	keys := make([]string, 0, len(r.Form))
	for k := range r.Form {
		keys = append(keys, k)
	}
	return keys
}
