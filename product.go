package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

var (
	validCategories    = map[string]struct{}{"Men": {}, "Women": {}, "Kids": {}}
	validSubcategories = map[string]struct{}{"Topwear": {}, "Bottomwear": {}}
	validSizes         = map[string]struct{}{"S": {}, "M": {}, "L": {}, "XL": {}}
)

type Product struct {
	ID          int64          `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Price       float64        `json:"price"`
	Category    string         `json:"category"`
	Subcategory string         `json:"subcategory"`
	Bestseller  bool           `json:"bestseller"`
	Show        bool           `json:"show"`
	Stock       []ProductStock `json:"stock_details"`
	Images      []ProductImage `json:"images"`
}

type ProductImage struct {
	ID    int64  `json:"id"`
	Image string `json:"image"`
}

type ProductStock struct {
	ID       int64  `json:"id"`
	Size     string `json:"size"`
	Quantity int    `json:"quantity"`
}

type productStockInput struct {
	Size     string `json:"size"`
	Quantity int    `json:"quantity"`
}

type productRepository struct {
	db      *sql.DB
	dialect string
}

var (
	repoOnce sync.Once
	repoInst *productRepository
	repoErr  error
)

func getProductRepository() (*productRepository, error) {
	repoOnce.Do(func() {
		driver, dsn, dialect, err := resolveDBConfig()
		if err != nil {
			repoErr = err
			return
		}
		db, err := sql.Open(driver, dsn)
		if err != nil {
			repoErr = err
			return
		}
		if dialect == "sqlite" {
			db.SetMaxOpenConns(1)
			if _, err := db.Exec("PRAGMA foreign_keys = ON;"); err != nil {
				repoErr = err
				_ = db.Close()
				return
			}
		}

		repoInst = &productRepository{db: db, dialect: dialect}
		repoErr = repoInst.migrate()
		if repoErr != nil {
			_ = db.Close()
			repoInst = nil
			return
		}
	})

	return repoInst, repoErr
}

func resolveDBConfig() (driver string, dsn string, dialect string, err error) {
	backend := strings.ToLower(strings.TrimSpace(os.Getenv("DB_BACKEND")))
	if backend == "" {
		backend = "sqlite"
	}

	switch backend {
	case "sqlite":
		dbPath := strings.TrimSpace(os.Getenv("SQLITE_PATH"))
		if dbPath == "" {
			dbPath = "test.db"
		}
		return "sqlite", dbPath, "sqlite", nil
	case "postgres", "postgresql":
		if url := strings.TrimSpace(os.Getenv("DATABASE_URL")); url != "" {
			return "pgx", url, "postgres", nil
		}
		host := strings.TrimSpace(os.Getenv("POSTGRES_HOST"))
		port := strings.TrimSpace(os.Getenv("POSTGRES_PORT"))
		user := strings.TrimSpace(os.Getenv("POSTGRES_USER"))
		password := strings.TrimSpace(os.Getenv("POSTGRES_PASSWORD"))
		dbName := strings.TrimSpace(os.Getenv("POSTGRES_DB"))
		sslMode := strings.TrimSpace(os.Getenv("POSTGRES_SSLMODE"))
		if sslMode == "" {
			sslMode = "disable"
		}
		if host == "" || port == "" || user == "" || dbName == "" {
			return "", "", "", errors.New("postgres requires POSTGRES_HOST, POSTGRES_PORT, POSTGRES_USER, POSTGRES_DB (or DATABASE_URL)")
		}
		dsn = fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s", host, port, user, password, dbName, sslMode)
		return "pgx", dsn, "postgres", nil
	default:
		return "", "", "", fmt.Errorf("unsupported DB_BACKEND: %s", backend)
	}
}

func (r *productRepository) migrate() error {
	var queries []string
	if r.dialect == "postgres" {
		queries = []string{
			`CREATE TABLE IF NOT EXISTS products (
				id BIGSERIAL PRIMARY KEY,
				name TEXT NOT NULL,
				description TEXT NOT NULL,
				price DOUBLE PRECISION NOT NULL,
				category TEXT NOT NULL,
				subcategory TEXT NOT NULL,
				bestseller INTEGER NOT NULL DEFAULT 0,
				show_flag INTEGER NOT NULL DEFAULT 1,
				created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
			);`,
			`CREATE TABLE IF NOT EXISTS product_images (
				id BIGSERIAL PRIMARY KEY,
				product_id BIGINT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
				image TEXT NOT NULL
			);`,
			`CREATE TABLE IF NOT EXISTS product_stock (
				id BIGSERIAL PRIMARY KEY,
				product_id BIGINT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
				size TEXT NOT NULL,
				quantity INTEGER NOT NULL DEFAULT 0,
				UNIQUE(product_id, size)
			);`,
			`CREATE INDEX IF NOT EXISTS idx_product_stock_product_size ON product_stock(product_id, size);`,
			`CREATE TABLE IF NOT EXISTS custom_users (
				id BIGSERIAL PRIMARY KEY,
				clerk_id TEXT NOT NULL UNIQUE,
				username TEXT NOT NULL,
				email TEXT NOT NULL,
				first_name TEXT NOT NULL DEFAULT '',
				last_name TEXT,
				role TEXT NOT NULL DEFAULT 'client',
				is_staff INTEGER NOT NULL DEFAULT 0,
				created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
				updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
			);`,
			`CREATE TABLE IF NOT EXISTS addresses (
				id BIGSERIAL PRIMARY KEY,
				user_id BIGINT NOT NULL UNIQUE REFERENCES custom_users(id) ON DELETE CASCADE,
				first_name TEXT NOT NULL,
				last_name TEXT NOT NULL,
				phone_number TEXT NOT NULL,
				address_line1 TEXT NOT NULL,
				street TEXT NOT NULL,
				city TEXT NOT NULL,
				state TEXT NOT NULL,
				postal_code TEXT NOT NULL
			);`,
			`CREATE TABLE IF NOT EXISTS carts (
				id BIGSERIAL PRIMARY KEY,
				user_id BIGINT NOT NULL UNIQUE REFERENCES custom_users(id) ON DELETE CASCADE
			);`,
			`CREATE TABLE IF NOT EXISTS cart_items (
				id BIGSERIAL PRIMARY KEY,
				cart_id BIGINT NOT NULL REFERENCES carts(id) ON DELETE CASCADE,
				product_id BIGINT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
				size TEXT NOT NULL,
				quantity INTEGER NOT NULL DEFAULT 1,
				UNIQUE(cart_id, product_id, size)
			);`,
			`CREATE INDEX IF NOT EXISTS idx_cart_items_cart_id ON cart_items(cart_id);`,
			`CREATE INDEX IF NOT EXISTS idx_cart_items_product_size ON cart_items(product_id, size);`,
			`CREATE TABLE IF NOT EXISTS orders (
				id BIGSERIAL PRIMARY KEY,
				user_id BIGINT NOT NULL REFERENCES custom_users(id) ON DELETE CASCADE,
				address_id BIGINT REFERENCES addresses(id) ON DELETE SET NULL,
				razorpay_order_id TEXT,
				razorpay_payment_id TEXT,
				razorpay_signature TEXT,
				total_amount BIGINT,
				consignment_number TEXT,
				delivery_status TEXT NOT NULL DEFAULT 'pending',
				created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
			);`,
			`CREATE TABLE IF NOT EXISTS order_items (
				id BIGSERIAL PRIMARY KEY,
				order_id BIGINT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
				product_id BIGINT REFERENCES products(id) ON DELETE SET NULL,
				size TEXT NOT NULL,
				quantity INTEGER,
				price BIGINT
			);`,
			`CREATE INDEX IF NOT EXISTS idx_orders_user_created ON orders(user_id, created_at DESC);`,
			`CREATE INDEX IF NOT EXISTS idx_order_items_order_id ON order_items(order_id);`,
		}
	} else {
		queries = []string{
			`CREATE TABLE IF NOT EXISTS products (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				name TEXT NOT NULL,
				description TEXT NOT NULL,
				price REAL NOT NULL,
				category TEXT NOT NULL,
				subcategory TEXT NOT NULL,
				bestseller INTEGER NOT NULL DEFAULT 0,
				show_flag INTEGER NOT NULL DEFAULT 1,
				created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
			);`,
			`CREATE TABLE IF NOT EXISTS product_images (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				product_id INTEGER NOT NULL,
				image TEXT NOT NULL,
				FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE
			);`,
			`CREATE TABLE IF NOT EXISTS product_stock (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				product_id INTEGER NOT NULL,
				size TEXT NOT NULL,
				quantity INTEGER NOT NULL DEFAULT 0,
				UNIQUE(product_id, size),
				FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE
			);`,
			`CREATE INDEX IF NOT EXISTS idx_product_stock_product_size ON product_stock(product_id, size);`,
			`CREATE TABLE IF NOT EXISTS custom_users (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				clerk_id TEXT NOT NULL UNIQUE,
				username TEXT NOT NULL,
				email TEXT NOT NULL,
				first_name TEXT NOT NULL DEFAULT '',
				last_name TEXT,
				role TEXT NOT NULL DEFAULT 'client',
				is_staff INTEGER NOT NULL DEFAULT 0,
				created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
			);`,
			`CREATE TABLE IF NOT EXISTS addresses (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				user_id INTEGER NOT NULL UNIQUE,
				first_name TEXT NOT NULL,
				last_name TEXT NOT NULL,
				phone_number TEXT NOT NULL,
				address_line1 TEXT NOT NULL,
				street TEXT NOT NULL,
				city TEXT NOT NULL,
				state TEXT NOT NULL,
				postal_code TEXT NOT NULL,
				FOREIGN KEY(user_id) REFERENCES custom_users(id) ON DELETE CASCADE
			);`,
			`CREATE TABLE IF NOT EXISTS carts (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				user_id INTEGER NOT NULL UNIQUE,
				FOREIGN KEY(user_id) REFERENCES custom_users(id) ON DELETE CASCADE
			);`,
			`CREATE TABLE IF NOT EXISTS cart_items (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				cart_id INTEGER NOT NULL,
				product_id INTEGER NOT NULL,
				size TEXT NOT NULL,
				quantity INTEGER NOT NULL DEFAULT 1,
				UNIQUE(cart_id, product_id, size),
				FOREIGN KEY(cart_id) REFERENCES carts(id) ON DELETE CASCADE,
				FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE
			);`,
			`CREATE INDEX IF NOT EXISTS idx_cart_items_cart_id ON cart_items(cart_id);`,
			`CREATE INDEX IF NOT EXISTS idx_cart_items_product_size ON cart_items(product_id, size);`,
			`CREATE TABLE IF NOT EXISTS orders (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				user_id INTEGER NOT NULL,
				address_id INTEGER,
				razorpay_order_id TEXT,
				razorpay_payment_id TEXT,
				razorpay_signature TEXT,
				total_amount INTEGER,
				consignment_number TEXT,
				delivery_status TEXT NOT NULL DEFAULT 'pending',
				created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				FOREIGN KEY(user_id) REFERENCES custom_users(id) ON DELETE CASCADE,
				FOREIGN KEY(address_id) REFERENCES addresses(id) ON DELETE SET NULL
			);`,
			`CREATE TABLE IF NOT EXISTS order_items (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				order_id INTEGER NOT NULL,
				product_id INTEGER,
				size TEXT NOT NULL,
				quantity INTEGER,
				price INTEGER,
				FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE,
				FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE SET NULL
			);`,
			`CREATE INDEX IF NOT EXISTS idx_orders_user_created ON orders(user_id, created_at DESC);`,
			`CREATE INDEX IF NOT EXISTS idx_order_items_order_id ON order_items(order_id);`,
		}
	}

	for _, q := range queries {
		if _, err := r.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

func (r *productRepository) listVisible(ctx context.Context) ([]Product, error) {
	rows, err := r.query(ctx, `
		SELECT id, name, description, price, category, subcategory, bestseller, show_flag
		FROM products
		WHERE show_flag = 1
		ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}

	products := make([]Product, 0)
	productIDs := make([]int64, 0)
	for rows.Next() {
		p, err := scanProductRow(rows)
		if err != nil {
			return nil, err
		}
		products = append(products, p)
		productIDs = append(productIDs, p.ID)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}

	if len(products) == 0 {
		return products, nil
	}

	stockByProduct, err := r.loadStockByProductIDs(ctx, productIDs)
	if err != nil {
		return nil, err
	}
	imagesByProduct, err := r.loadImagesByProductIDs(ctx, productIDs)
	if err != nil {
		return nil, err
	}

	for i := range products {
		products[i].Stock = stockByProduct[products[i].ID]
		products[i].Images = imagesByProduct[products[i].ID]
	}

	return products, nil
}

func (r *productRepository) get(ctx context.Context, id int64) (Product, bool, error) {
	row := r.queryRow(ctx, `
		SELECT id, name, description, price, category, subcategory, bestseller, show_flag
		FROM products
		WHERE id = ?`, id)

	p, err := scanProductSingleRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Product{}, false, nil
	}
	if err != nil {
		return Product{}, false, err
	}

	if err := r.loadRelations(ctx, &p); err != nil {
		return Product{}, false, err
	}
	return p, true, nil
}

func (r *productRepository) create(ctx context.Context, p Product, stocks []productStockInput, imageURLs []string) (Product, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return Product{}, err
	}
	defer tx.Rollback()

	insertProductQuery := `
		INSERT INTO products(name, description, price, category, subcategory, bestseller, show_flag)
		VALUES(?, ?, ?, ?, ?, ?, ?)`
	args := []any{p.Name, p.Description, p.Price, p.Category, p.Subcategory, boolToInt(p.Bestseller), boolToInt(p.Show)}

	var productID int64
	if r.dialect == "postgres" {
		if err := tx.QueryRowContext(ctx, rebindQuery(insertProductQuery+" RETURNING id", r.dialect), args...).Scan(&productID); err != nil {
			return Product{}, err
		}
	} else {
		res, err := tx.ExecContext(ctx, rebindQuery(insertProductQuery, r.dialect), args...)
		if err != nil {
			return Product{}, err
		}
		productID, err = res.LastInsertId()
		if err != nil {
			return Product{}, err
		}
	}

	for _, s := range stocks {
		if _, err := tx.ExecContext(ctx, rebindQuery(`
			INSERT INTO product_stock(product_id, size, quantity)
			VALUES(?, ?, ?)`, r.dialect), productID, s.Size, s.Quantity); err != nil {
			return Product{}, err
		}
	}

	for _, imageURL := range imageURLs {
		if _, err := tx.ExecContext(ctx, rebindQuery(`
			INSERT INTO product_images(product_id, image)
			VALUES(?, ?)`, r.dialect), productID, imageURL); err != nil {
			return Product{}, err
		}
	}

	if err := tx.Commit(); err != nil {
		return Product{}, err
	}

	created, ok, err := r.get(ctx, productID)
	if err != nil {
		return Product{}, err
	}
	if !ok {
		return Product{}, errors.New("failed to fetch created product")
	}
	return created, nil
}

func (r *productRepository) updateStock(ctx context.Context, id int64, stocks []productStockInput) (bool, error) {
	exists, err := r.productExists(ctx, id)
	if err != nil {
		return false, err
	}
	if !exists {
		return false, nil
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, rebindQuery(`DELETE FROM product_stock WHERE product_id = ?`, r.dialect), id); err != nil {
		return false, err
	}

	for _, s := range stocks {
		if _, err := tx.ExecContext(ctx, rebindQuery(`
			INSERT INTO product_stock(product_id, size, quantity)
			VALUES(?, ?, ?)`, r.dialect), id, s.Size, s.Quantity); err != nil {
			return false, err
		}
	}

	if err := tx.Commit(); err != nil {
		return false, err
	}

	return true, nil
}

func (r *productRepository) softDelete(ctx context.Context, id int64) (bool, error) {
	res, err := r.exec(ctx, `UPDATE products SET show_flag = 0 WHERE id = ?`, id)
	if err != nil {
		return false, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected > 0, nil
}

func (r *productRepository) productExists(ctx context.Context, id int64) (bool, error) {
	var exists int
	err := r.queryRow(ctx, `SELECT 1 FROM products WHERE id = ?`, id).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (r *productRepository) loadRelations(ctx context.Context, p *Product) error {
	stocks, err := r.loadStock(ctx, p.ID)
	if err != nil {
		return err
	}
	images, err := r.loadImages(ctx, p.ID)
	if err != nil {
		return err
	}
	p.Stock = stocks
	p.Images = images
	return nil
}

func (r *productRepository) loadStock(ctx context.Context, productID int64) ([]ProductStock, error) {
	rows, err := r.query(ctx, `
		SELECT id, size, quantity
		FROM product_stock
		WHERE product_id = ?
		ORDER BY id ASC`, productID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stocks := make([]ProductStock, 0)
	for rows.Next() {
		var s ProductStock
		if err := rows.Scan(&s.ID, &s.Size, &s.Quantity); err != nil {
			return nil, err
		}
		stocks = append(stocks, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return stocks, nil
}

func (r *productRepository) loadImages(ctx context.Context, productID int64) ([]ProductImage, error) {
	rows, err := r.query(ctx, `
		SELECT id, image
		FROM product_images
		WHERE product_id = ?
		ORDER BY id ASC`, productID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	images := make([]ProductImage, 0)
	for rows.Next() {
		var img ProductImage
		if err := rows.Scan(&img.ID, &img.Image); err != nil {
			return nil, err
		}
		images = append(images, img)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return images, nil
}

func (r *productRepository) loadStockByProductIDs(ctx context.Context, productIDs []int64) (map[int64][]ProductStock, error) {
	result := make(map[int64][]ProductStock, len(productIDs))
	if len(productIDs) == 0 {
		return result, nil
	}

	args := make([]any, 0, len(productIDs))
	for _, id := range productIDs {
		args = append(args, id)
		result[id] = []ProductStock{}
	}

	query := fmt.Sprintf(`
		SELECT id, product_id, size, quantity
		FROM product_stock
		WHERE product_id IN (%s)
		ORDER BY id ASC`, placeholders(len(productIDs)))
	rows, err := r.query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var s ProductStock
		var productID int64
		if err := rows.Scan(&s.ID, &productID, &s.Size, &s.Quantity); err != nil {
			return nil, err
		}
		result[productID] = append(result[productID], s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return result, nil
}

func (r *productRepository) loadImagesByProductIDs(ctx context.Context, productIDs []int64) (map[int64][]ProductImage, error) {
	result := make(map[int64][]ProductImage, len(productIDs))
	if len(productIDs) == 0 {
		return result, nil
	}

	args := make([]any, 0, len(productIDs))
	for _, id := range productIDs {
		args = append(args, id)
		result[id] = []ProductImage{}
	}

	query := fmt.Sprintf(`
		SELECT id, product_id, image
		FROM product_images
		WHERE product_id IN (%s)
		ORDER BY id ASC`, placeholders(len(productIDs)))
	rows, err := r.query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var img ProductImage
		var productID int64
		if err := rows.Scan(&img.ID, &productID, &img.Image); err != nil {
			return nil, err
		}
		result[productID] = append(result[productID], img)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return result, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanProductRow(s rowScanner) (Product, error) {
	var p Product
	var bestseller int
	var show int
	if err := s.Scan(&p.ID, &p.Name, &p.Description, &p.Price, &p.Category, &p.Subcategory, &bestseller, &show); err != nil {
		return Product{}, err
	}
	p.Bestseller = bestseller == 1
	p.Show = show == 1
	return p, nil
}

func scanProductSingleRow(row *sql.Row) (Product, error) {
	return scanProductRow(row)
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func (r *productRepository) exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return r.db.ExecContext(ctx, rebindQuery(query, r.dialect), args...)
}

func (r *productRepository) query(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return r.db.QueryContext(ctx, rebindQuery(query, r.dialect), args...)
}

func (r *productRepository) queryRow(ctx context.Context, query string, args ...any) *sql.Row {
	return r.db.QueryRowContext(ctx, rebindQuery(query, r.dialect), args...)
}

func rebindQuery(query, dialect string) string {
	if dialect != "postgres" {
		return query
	}
	var n int
	placeholder := regexp.MustCompile(`\?`)
	return placeholder.ReplaceAllStringFunc(query, func(_ string) string {
		n++
		return fmt.Sprintf("$%d", n)
	})
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

func registerProductRoutes(mux *http.ServeMux) {
	mux.Handle("/api/products", ClerkMiddleware(http.HandlerFunc(productsListCreateHandler)))
	mux.Handle("/api/products/", ClerkMiddleware(http.HandlerFunc(apiProductsRouter)))
	mux.Handle("/api/products/delete/", ClerkMiddleware(http.HandlerFunc(productDeleteHandler)))

	mux.Handle("/products", ClerkMiddleware(http.HandlerFunc(productsListCreateHandler)))
	mux.Handle("/products/", ClerkMiddleware(http.HandlerFunc(productsRouter)))
	mux.Handle("/products/delete/", ClerkMiddleware(http.HandlerFunc(productDeleteHandler)))

	if !useS3Enabled() {
		mux.Handle("/media/", http.StripPrefix("/media/", http.FileServer(http.Dir("media"))))
	}
}

func apiProductsRouter(w http.ResponseWriter, r *http.Request) {
	if normalizePath(r.URL.Path) == "/api/products" {
		productsListCreateHandler(w, r)
		return
	}
	productsDetailRouter(w, r)
}

func productsRouter(w http.ResponseWriter, r *http.Request) {
	if normalizePath(r.URL.Path) == "/products" {
		productsListCreateHandler(w, r)
		return
	}
	productsDetailRouter(w, r)
}

func normalizePath(path string) string {
	path = strings.TrimSpace(path)
	for strings.HasSuffix(path, "/") && len(path) > 1 {
		path = strings.TrimSuffix(path, "/")
	}
	return path
}

func productsListCreateHandler(w http.ResponseWriter, r *http.Request) {
	repo, err := getProductRepository()
	if err != nil {
		logErrorWithTrace("database initialization failed", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "database initialization failed"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		items, err := repo.listVisible(r.Context())
		if err != nil {
			if isRequestCanceled(err) {
				log.Printf("products list request canceled by client: %v", err)
				return
			}
			logErrorWithTrace("failed to fetch products", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "failed to fetch products"})
			return
		}
		writeJSON(w, http.StatusOK, items)
	case http.MethodPost:
		if !requireWriteAccess(w, r) {
			return
		}
		handleCreateProduct(w, r, repo)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func productsDetailRouter(w http.ResponseWriter, r *http.Request) {
	repo, err := getProductRepository()
	if err != nil {
		logErrorWithTrace("database initialization failed", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "database initialization failed"})
		return
	}

	if strings.HasPrefix(r.URL.Path, "/products/delete/") || strings.HasPrefix(r.URL.Path, "/api/products/delete/") {
		productDeleteHandler(w, r)
		return
	}

	id, err := parseProductIDFromPath(r.URL.Path)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "Product not found."})
		return
	}

	switch r.Method {
	case http.MethodGet:
		p, ok, err := repo.get(r.Context(), id)
		if err != nil {
			logErrorWithTrace("failed to fetch product", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "failed to fetch product"})
			return
		}
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"detail": "Product not found."})
			return
		}
		writeJSON(w, http.StatusOK, p)
	case http.MethodPut:
		if !requireWriteAccess(w, r) {
			return
		}
		stock, err := parseStockDetails(r)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"stock_details": "Invalid JSON."})
			return
		}
		if err := validateStockInputs(stock); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": err.Error()})
			return
		}

		ok, err := repo.updateStock(r.Context(), id, stock)
		if err != nil {
			logErrorWithTrace("failed to update stock", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "failed to update stock"})
			return
		}
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"detail": "Product not found."})
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{"detail": "Stock updated successfully."})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func productDeleteHandler(w http.ResponseWriter, r *http.Request) {
	repo, err := getProductRepository()
	if err != nil {
		logErrorWithTrace("database initialization failed", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "database initialization failed"})
		return
	}

	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireWriteAccess(w, r) {
		return
	}

	id, err := parseDeleteProductIDFromPath(r.URL.Path)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "Product not found."})
		return
	}

	ok, err := repo.softDelete(r.Context(), id)
	if err != nil {
		logErrorWithTrace("failed to delete product", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "failed to delete product"})
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "Product not found."})
		return
	}

	writeJSON(w, http.StatusNoContent, map[string]string{"detail": "Product deleted successfully."})
}

func handleCreateProduct(w http.ResponseWriter, r *http.Request, repo *productRepository) {
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "Invalid multipart form."})
		return
	}

	stock, err := parseStockDetails(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"stock_details": "Invalid JSON."})
		return
	}
	if err := validateStockInputs(stock); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": err.Error()})
		return
	}

	price, err := strconv.ParseFloat(strings.TrimSpace(r.FormValue("price")), 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "price must be a valid number"})
		return
	}

	category := strings.TrimSpace(r.FormValue("category"))
	if _, ok := validCategories[category]; !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "category must be Men, Women, or Kids"})
		return
	}

	subcategory := strings.TrimSpace(r.FormValue("subcategory"))
	if _, ok := validSubcategories[subcategory]; !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "subcategory must be Topwear or Bottomwear"})
		return
	}

	bestseller := parseBoolWithDefault(r.FormValue("bestseller"), false)
	show := parseBoolWithDefault(r.FormValue("show"), true)

	imageURLs, err := saveUploadedImages(r.MultipartForm.File["images"])
	if err != nil {
		logErrorWithTrace("failed to save uploaded images", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "failed to save uploaded images"})
		return
	}

	product, err := repo.create(r.Context(), Product{
		Name:        strings.TrimSpace(r.FormValue("name")),
		Description: strings.TrimSpace(r.FormValue("description")),
		Price:       price,
		Category:    category,
		Subcategory: subcategory,
		Bestseller:  bestseller,
		Show:        show,
	}, stock, imageURLs)
	if err != nil {
		logErrorWithTrace("failed to create product", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "failed to create product"})
		return
	}

	writeJSON(w, http.StatusCreated, product)
}

func parseStockDetails(r *http.Request) ([]productStockInput, error) {
	ctype := r.Header.Get("Content-Type")

	if strings.Contains(ctype, "application/json") {
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			return nil, err
		}

		raw, ok := payload["stock_details"]
		if !ok || raw == nil {
			return []productStockInput{}, nil
		}

		// Accept native JSON arrays: {"stock_details":[...]}
		if arr, ok := raw.([]any); ok {
			b, err := json.Marshal(arr)
			if err != nil {
				return nil, err
			}
			var stock []productStockInput
			if err := json.Unmarshal(b, &stock); err != nil {
				return nil, err
			}
			return stock, nil
		}

		// Accept stringified JSON arrays:
		// {"stock_details":"[{\"size\":\"M\",\"quantity\":7}]"}
		if s, ok := raw.(string); ok {
			s = strings.TrimSpace(s)
			if s == "" {
				return []productStockInput{}, nil
			}
			var stock []productStockInput
			if err := json.Unmarshal([]byte(s), &stock); err != nil {
				return nil, err
			}
			return stock, nil
		}

		return nil, errors.New("stock_details must be array or stringified array")
	}

	raw := strings.TrimSpace(r.FormValue("stock_details"))
	if raw == "" {
		return []productStockInput{}, nil
	}

	var stock []productStockInput
	if err := json.Unmarshal([]byte(raw), &stock); err != nil {
		return nil, err
	}
	return stock, nil
}

func validateStockInputs(stock []productStockInput) error {
	seen := make(map[string]struct{}, len(stock))
	for _, s := range stock {
		if _, ok := validSizes[s.Size]; !ok {
			return errors.New("size must be one of S, M, L, XL")
		}
		if s.Quantity < 0 {
			return errors.New("quantity must be zero or positive")
		}
		if _, exists := seen[s.Size]; exists {
			return fmt.Errorf("duplicate size: %s", s.Size)
		}
		seen[s.Size] = struct{}{}
	}
	return nil
}

func parseProductIDFromPath(path string) (int64, error) {
	if strings.HasPrefix(path, "/api/products/") {
		return parseProductID(path, "/api/products/")
	}
	return parseProductID(path, "/products/")
}

func parseDeleteProductIDFromPath(path string) (int64, error) {
	if strings.HasPrefix(path, "/api/products/delete/") {
		return parseProductID(path, "/api/products/delete/")
	}
	return parseProductID(path, "/products/delete/")
}

func parseProductID(path, prefix string) (int64, error) {
	trimmed := strings.TrimSuffix(strings.TrimPrefix(path, prefix), "/")
	if trimmed == "" || strings.Contains(trimmed, "/") {
		return 0, errors.New("invalid id")
	}
	return strconv.ParseInt(trimmed, 10, 64)
}

func saveUploadedImages(files []*multipart.FileHeader) ([]string, error) {
	if len(files) == 0 {
		return nil, nil
	}

	urls := make([]string, 0, len(files))
	for _, fileHeader := range files {
		url, err := saveSingleImage(fileHeader)
		if err != nil {
			return nil, err
		}
		urls = append(urls, url)
	}
	return urls, nil
}

func saveSingleImage(fileHeader *multipart.FileHeader) (string, error) {
	if useS3Enabled() {
		return saveSingleImageToS3(fileHeader)
	}
	return saveSingleImageLocal(fileHeader)
}

// allowedImageMIMEs is the set of MIME types accepted for product images.
var allowedImageMIMEs = map[string]bool{
	"image/jpeg": true,
	"image/png":  true,
	"image/gif":  true,
	"image/webp": true,
}

// detectAndValidateMIME reads the first 512 bytes from the file to sniff the
// content type, resets the reader, and returns an error if not an allowed image.
func detectAndValidateMIME(f io.ReadSeeker) (string, error) {
	buf := make([]byte, 512)
	n, err := f.Read(buf)
	if err != nil && err != io.EOF {
		return "", err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	mime := http.DetectContentType(buf[:n])
	// DetectContentType may return "image/jpeg; charset=..." — strip params.
	if idx := strings.Index(mime, ";"); idx != -1 {
		mime = strings.TrimSpace(mime[:idx])
	}
	if !allowedImageMIMEs[mime] {
		return "", fmt.Errorf("unsupported file type %q: only JPEG, PNG, GIF, WEBP are allowed", mime)
	}
	return mime, nil
}

func saveSingleImageLocal(fileHeader *multipart.FileHeader) (string, error) {
	if err := os.MkdirAll(filepath.Join("media", "product_images"), 0o755); err != nil {
		return "", err
	}

	src, err := fileHeader.Open()
	if err != nil {
		return "", err
	}
	defer src.Close()

	// Validate actual file content, not just extension.
	detectedMIME, err := detectAndValidateMIME(src)
	if err != nil {
		return "", err
	}

	ext := mimeToExt(detectedMIME)

	base := strings.TrimSuffix(filepath.Base(fileHeader.Filename), filepath.Ext(fileHeader.Filename))
	safeBase := sanitizeFilename(base)
	if safeBase == "" {
		safeBase = "image"
	}

	filename := fmt.Sprintf("%s_%d%s", safeBase, time.Now().UnixNano(), ext)
	filePath := filepath.Join("media", "product_images", filename)

	dst, err := os.Create(filePath)
	if err != nil {
		return "", err
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return "", err
	}

	return "/media/product_images/" + filename, nil
}

func mimeToExt(mime string) string {
	switch mime {
	case "image/png":
		return ".png"
	case "image/gif":
		return ".gif"
	case "image/webp":
		return ".webp"
	default:
		return ".jpg"
	}
}

var (
	s3InitOnce sync.Once
	s3InitErr  error
	uploader   *manager.Uploader
	bucketName string
	regionName string
	cdnDomain  string
)

func initS3Uploader() error {
	s3InitOnce.Do(func() {
		bucketName = strings.TrimSpace(os.Getenv("AWS_STORAGE_BUCKET_NAME"))
		regionName = strings.TrimSpace(os.Getenv("AWS_S3_REGION_NAME"))
		cdnDomain = strings.TrimSpace(os.Getenv("AWS_S3_CUSTOM_DOMAIN"))

		if bucketName == "" {
			s3InitErr = errors.New("AWS_STORAGE_BUCKET_NAME is required when USE_S3=true")
			return
		}
		if regionName == "" {
			s3InitErr = errors.New("AWS_S3_REGION_NAME is required when USE_S3=true")
			return
		}

		cfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion(regionName))
		if err != nil {
			s3InitErr = err
			return
		}

		uploader = manager.NewUploader(s3.NewFromConfig(cfg))
	})
	return s3InitErr
}

func saveSingleImageToS3(fileHeader *multipart.FileHeader) (string, error) {
	if err := initS3Uploader(); err != nil {
		return "", err
	}

	src, err := fileHeader.Open()
	if err != nil {
		return "", err
	}
	defer src.Close()

	// Validate actual file content, not just extension or client-provided MIME.
	detectedMIME, err := detectAndValidateMIME(src)
	if err != nil {
		return "", err
	}

	ext := mimeToExt(detectedMIME)
	contentType := detectedMIME

	base := strings.TrimSuffix(filepath.Base(fileHeader.Filename), filepath.Ext(fileHeader.Filename))
	safeBase := sanitizeFilename(base)
	if safeBase == "" {
		safeBase = "image"
	}

	filename := fmt.Sprintf("%s_%d%s", safeBase, time.Now().UnixNano(), ext)
	key := "media/product_images/" + filename

	_, err = uploader.Upload(context.Background(), &s3.PutObjectInput{
		Bucket:       &bucketName,
		Key:          &key,
		Body:         src,
		ContentType:  &contentType,
		CacheControl: strPtr("max-age=86400"),
	})
	if err != nil {
		return "", err
	}

	if cdnDomain != "" {
		return "https://" + strings.TrimRight(cdnDomain, "/") + "/" + key, nil
	}
	return fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s", bucketName, regionName, key), nil
}

func useS3Enabled() bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv("USE_S3")))
	if raw == "" {
		return true
	}
	switch raw {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		log.Printf("invalid USE_S3 value %q, defaulting to true", raw)
		return true
	}
}

func sanitizeFilename(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune(r)
		case r == ' ':
			b.WriteRune('_')
		}
	}
	return b.String()
}

func parseBoolWithDefault(raw string, fallback bool) bool {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return fallback
	}
	switch raw {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return fallback
	}
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func requireWriteAccess(w http.ResponseWriter, r *http.Request) bool {
	user, ok := FromContext(r.Context())
	if !ok || user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"detail": "authentication required"})
		return false
	}

	appUser, found, err := getCustomUserByClerkID(r.Context(), user.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "failed to resolve user role"})
		return false
	}
	if !found {
		writeJSON(w, http.StatusForbidden, map[string]string{"detail": "manager access required"})
		return false
	}
	if appUser.Role == "manager" {
		return true
	}

	writeJSON(w, http.StatusForbidden, map[string]string{"detail": "manager access required"})
	return false
}

func strPtr(s string) *string {
	return &s
}

func isRequestCanceled(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
