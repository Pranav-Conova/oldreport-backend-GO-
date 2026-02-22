# oldreport-go-backend

Go backend with Clerk-auth middleware and product APIs.

Endpoints:

- `GET /health` returns `{\"status\":\"ok\"}`
- `GET /protected` returns authenticated Clerk user profile
- `GET /api/products` lists only products where `show=true`
- `POST /api/products` creates a product (auth required; manager-gated if `MANAGER_EMAILS` is set)
- `GET /api/products/{id}` returns one product (including hidden)
- `PUT /api/products/{id}` replaces stock details only
- `DELETE /api/products/delete/{id}` soft-deletes a product (`show=false`)
- `GET /api/cart` (or `/api/cart/`) returns authenticated user's cart
- `POST /api/cart` adds an item to authenticated user's cart
- `PUT /api/cart` updates quantity of an existing cart item
- `DELETE /api/cart` removes an item from cart using `item_id`
- `GET /role` (or `/role/`) returns authenticated user's `username`, `email`, `role`
- `GET /address` (or `/address/`) returns authenticated user's address
- `POST /address` creates/updates authenticated user's address

Backward-compatible aliases are also available under `/products...`.

Create product request format (`multipart/form-data`):

- text fields: `name`, `description`, `price`, `category`, `subcategory`, optional `bestseller`, optional `show`
- `stock_details`: JSON string like `[{\"size\":\"M\",\"quantity\":10}]`
- one or more `images` files

Storage:

- `USE_S3=true` (default): uploads to S3 key path `media/product_images/*`
- If `AWS_S3_CUSTOM_DOMAIN` is set (CloudFront/custom CDN), image URLs use that domain
- `USE_S3=false`: uploads saved locally under `media/product_images/` and served at `/media/...`

Required S3 env vars when `USE_S3=true`:

- `AWS_STORAGE_BUCKET_NAME`
- `AWS_S3_REGION_NAME`
- optional `AWS_S3_CUSTOM_DOMAIN`

Notes:

- Category choices: `Men`, `Women`, `Kids`
- Subcategory choices: `Topwear`, `Bottomwear`
- Size choices: `S`, `M`, `L`, `XL`
- Product write actions (`POST/PUT/DELETE`) require authenticated user role `manager`
- On authenticated requests, Clerk middleware auto-syncs user into `custom_users` if missing
- Cart endpoints require authentication
- Cart `POST`/`PUT`/`DELETE` expect a JSON request body; invalid JSON returns:
  `{"error":"Invalid JSON body."}`
Database:

- `DB_BACKEND=sqlite` for testing (default), using `SQLITE_PATH=test.db`
- `DB_BACKEND=postgres` for production, using either:
- `DATABASE_URL`, or
- `POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`, `POSTGRES_SSLMODE`

Run locally:

```powershell
go run .
```
# oldreport-backend-GO-
