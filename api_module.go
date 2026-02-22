package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

type CustomUser struct {
	ID        int64  `json:"id"`
	ClerkID   string `json:"-"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name,omitempty"`
	Role      string `json:"role"`
	IsStaff   bool   `json:"is_staff"`
}

type Address struct {
	ID          int64  `json:"id"`
	UserID      int64  `json:"user"`
	FirstName   string `json:"first_name"`
	LastName    string `json:"Last_name"`
	PhoneNumber string `json:"phone_number"`
	AddressLine string `json:"address_line1"`
	Street      string `json:"street"`
	City        string `json:"city"`
	State       string `json:"state"`
	PostalCode  string `json:"postal_code"`
}

type addressPayload struct {
	FirstName   *string `json:"first_name"`
	LastName    *string `json:"Last_name"`
	PhoneNumber *string `json:"phone_number"`
	AddressLine *string `json:"address_line1"`
	Street      *string `json:"street"`
	City        *string `json:"city"`
	State       *string `json:"state"`
	PostalCode  *string `json:"postal_code"`
}

func registerAPIRoutes(mux *http.ServeMux) {
	mux.Handle("/role/", ClerkMiddleware(http.HandlerFunc(userRoleHandler)))
	mux.Handle("/role", ClerkMiddleware(http.HandlerFunc(userRoleHandler)))
	mux.Handle("/address/", ClerkMiddleware(http.HandlerFunc(userAddressHandler)))
	mux.Handle("/address", ClerkMiddleware(http.HandlerFunc(userAddressHandler)))
}

func userRoleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clerkUser, ok := FromContext(r.Context())
	if !ok || clerkUser == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"detail": "authentication required"})
		return
	}

	user, found, err := getCustomUserByClerkID(r.Context(), clerkUser.ID)
	if err != nil {
		logErrorWithTrace("failed to fetch user", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "failed to fetch user"})
		return
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "User not found."})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"username": user.Username,
		"email":    user.Email,
		"role":     user.Role,
	})
}

func userAddressHandler(w http.ResponseWriter, r *http.Request) {
	clerkUser, ok := FromContext(r.Context())
	if !ok || clerkUser == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"detail": "authentication required"})
		return
	}

	user, found, err := getCustomUserByClerkID(r.Context(), clerkUser.ID)
	if err != nil {
		logErrorWithTrace("failed to fetch user", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "failed to fetch user"})
		return
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"detail": "User not found."})
		return
	}

	switch r.Method {
	case http.MethodGet:
		addr, found, err := getAddressByUserID(r.Context(), user.ID)
		if err != nil {
			logErrorWithTrace("failed to fetch address", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "failed to fetch address"})
			return
		}
		if !found {
			writeJSON(w, http.StatusOK, map[string]any{})
			return
		}
		writeJSON(w, http.StatusOK, addr)
	case http.MethodPost:
		payload, err := parseAddressPayload(r)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": "Invalid JSON body."})
			return
		}

		addr, exists, err := getAddressByUserID(r.Context(), user.ID)
		if err != nil {
			logErrorWithTrace("failed to fetch address", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"detail": "failed to fetch address"})
			return
		}

		if exists {
			updated, err := updateAddressPartial(r.Context(), addr.ID, payload)
			if err != nil {
				logErrorWithTrace("failed to update address", err)
				writeJSON(w, http.StatusBadRequest, map[string]string{"detail": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, updated)
			return
		}

		created, err := createAddress(r.Context(), user.ID, payload)
		if err != nil {
			logErrorWithTrace("failed to create address", err)
			writeJSON(w, http.StatusBadRequest, map[string]string{"detail": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, created)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func parseAddressPayload(r *http.Request) (addressPayload, error) {
	ctype := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
	if strings.Contains(ctype, "application/json") {
		var payload addressPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			return addressPayload{}, err
		}
		return payload, nil
	}

	if strings.Contains(ctype, "multipart/form-data") {
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			return addressPayload{}, err
		}
	} else {
		if err := r.ParseForm(); err != nil {
			return addressPayload{}, err
		}
	}

	val := func(keys ...string) *string {
		for _, k := range keys {
			v := strings.TrimSpace(r.FormValue(k))
			if v != "" {
				vCopy := v
				return &vCopy
			}
		}
		return nil
	}

	return addressPayload{
		FirstName:   val("first_name", "firstName"),
		LastName:    val("Last_name", "last_name", "lastName"),
		PhoneNumber: val("phone_number", "phoneNumber"),
		AddressLine: val("address_line1", "addressLine1"),
		Street:      val("street"),
		City:        val("city"),
		State:       val("state"),
		PostalCode:  val("postal_code", "postalCode"),
	}, nil
}

func ensureCustomUserFromClerk(ctx context.Context, clerkUser *ClerkUser) (*CustomUser, error) {
	repo, err := getProductRepository()
	if err != nil {
		return nil, err
	}

	username := buildUsername(clerkUser)
	query := `
		INSERT INTO custom_users(clerk_id, username, email, first_name, last_name, role, is_staff)
		VALUES(?, ?, ?, ?, ?, 'client', 0)
		ON CONFLICT(clerk_id) DO UPDATE SET
			username=excluded.username,
			email=excluded.email,
			first_name=excluded.first_name,
			last_name=excluded.last_name,
			updated_at=CURRENT_TIMESTAMP`
	if repo.dialect == "postgres" {
		query = `
			INSERT INTO custom_users(clerk_id, username, email, first_name, last_name, role, is_staff)
			VALUES(?, ?, ?, ?, ?, 'client', 0)
			ON CONFLICT(clerk_id) DO UPDATE SET
				username=EXCLUDED.username,
				email=EXCLUDED.email,
				first_name=EXCLUDED.first_name,
				last_name=EXCLUDED.last_name,
				updated_at=NOW()`
	}

	if _, err := repo.db.ExecContext(ctx, rebindQuery(query, repo.dialect), clerkUser.ID, username, clerkUser.Email, clerkUser.FirstName, nullIfEmpty(clerkUser.LastName)); err != nil {
		return nil, err
	}

	user, _, err := getCustomUserByClerkID(ctx, clerkUser.ID)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func getCustomUserByClerkID(ctx context.Context, clerkID string) (CustomUser, bool, error) {
	repo, err := getProductRepository()
	if err != nil {
		return CustomUser{}, false, err
	}

	row := repo.queryRow(ctx, `
		SELECT id, clerk_id, username, email, first_name, COALESCE(last_name, ''), role, is_staff
		FROM custom_users
		WHERE clerk_id = ?`, clerkID)

	var user CustomUser
	var isStaff int
	err = row.Scan(&user.ID, &user.ClerkID, &user.Username, &user.Email, &user.FirstName, &user.LastName, &user.Role, &isStaff)
	if errors.Is(err, sql.ErrNoRows) {
		return CustomUser{}, false, nil
	}
	if err != nil {
		return CustomUser{}, false, err
	}
	user.IsStaff = isStaff == 1
	return user, true, nil
}

func getAddressByUserID(ctx context.Context, userID int64) (Address, bool, error) {
	repo, err := getProductRepository()
	if err != nil {
		return Address{}, false, err
	}

	row := repo.queryRow(ctx, `
		SELECT id, user_id, first_name, last_name, phone_number, address_line1, street, city, state, postal_code
		FROM addresses
		WHERE user_id = ?`, userID)

	var a Address
	err = row.Scan(&a.ID, &a.UserID, &a.FirstName, &a.LastName, &a.PhoneNumber, &a.AddressLine, &a.Street, &a.City, &a.State, &a.PostalCode)
	if errors.Is(err, sql.ErrNoRows) {
		return Address{}, false, nil
	}
	if err != nil {
		return Address{}, false, err
	}
	return a, true, nil
}

func createAddress(ctx context.Context, userID int64, p addressPayload) (Address, error) {
	repo, err := getProductRepository()
	if err != nil {
		return Address{}, err
	}

	if p.FirstName == nil || p.LastName == nil || p.PhoneNumber == nil || p.AddressLine == nil || p.Street == nil || p.City == nil || p.State == nil || p.PostalCode == nil {
		return Address{}, errors.New("all address fields are required for create")
	}

	q := `
		INSERT INTO addresses(user_id, first_name, last_name, phone_number, address_line1, street, city, state, postal_code)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if _, err := repo.db.ExecContext(ctx, rebindQuery(q, repo.dialect), userID,
		strings.TrimSpace(*p.FirstName),
		strings.TrimSpace(*p.LastName),
		strings.TrimSpace(*p.PhoneNumber),
		strings.TrimSpace(*p.AddressLine),
		strings.TrimSpace(*p.Street),
		strings.TrimSpace(*p.City),
		strings.TrimSpace(*p.State),
		strings.TrimSpace(*p.PostalCode),
	); err != nil {
		return Address{}, err
	}

	addr, found, err := getAddressByUserID(ctx, userID)
	if err != nil {
		return Address{}, err
	}
	if !found {
		return Address{}, errors.New("failed to create address")
	}
	return addr, nil
}

func updateAddressPartial(ctx context.Context, addressID int64, p addressPayload) (Address, error) {
	repo, err := getProductRepository()
	if err != nil {
		return Address{}, err
	}

	sets := make([]string, 0, 8)
	args := make([]any, 0, 9)

	appendField := func(name string, value *string) {
		if value == nil {
			return
		}
		sets = append(sets, name+" = ?")
		args = append(args, strings.TrimSpace(*value))
	}

	appendField("first_name", p.FirstName)
	appendField("last_name", p.LastName)
	appendField("phone_number", p.PhoneNumber)
	appendField("address_line1", p.AddressLine)
	appendField("street", p.Street)
	appendField("city", p.City)
	appendField("state", p.State)
	appendField("postal_code", p.PostalCode)

	if len(sets) == 0 {
		return getAddressByID(ctx, addressID)
	}

	args = append(args, addressID)
	query := "UPDATE addresses SET " + strings.Join(sets, ", ") + " WHERE id = ?"
	if _, err := repo.db.ExecContext(ctx, rebindQuery(query, repo.dialect), args...); err != nil {
		return Address{}, err
	}

	return getAddressByID(ctx, addressID)
}

func getAddressByID(ctx context.Context, addressID int64) (Address, error) {
	repo, err := getProductRepository()
	if err != nil {
		return Address{}, err
	}

	row := repo.queryRow(ctx, `
		SELECT id, user_id, first_name, last_name, phone_number, address_line1, street, city, state, postal_code
		FROM addresses
		WHERE id = ?`, addressID)

	var a Address
	if err := row.Scan(&a.ID, &a.UserID, &a.FirstName, &a.LastName, &a.PhoneNumber, &a.AddressLine, &a.Street, &a.City, &a.State, &a.PostalCode); err != nil {
		return Address{}, err
	}
	return a, nil
}

func buildUsername(clerkUser *ClerkUser) string {
	if clerkUser == nil {
		return "user"
	}
	candidate := sanitizeIdentifier(clerkUser.ID)
	if candidate == "" {
		return "user"
	}
	return candidate
}

func sanitizeIdentifier(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '_' || r == '-':
			b.WriteRune(r)
		case r == '.':
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "user"
	}
	return b.String()
}

func nullIfEmpty(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}
