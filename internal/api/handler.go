package api

import (
	"net/http"

	"github.com/bootdotdev/learn-web-security/internal/accounts"
	"github.com/bootdotdev/learn-web-security/internal/auth/sessions"
	"github.com/bootdotdev/learn-web-security/internal/httpx"
	"github.com/bootdotdev/learn-web-security/internal/logging"
	"github.com/bootdotdev/learn-web-security/internal/orders"
	"github.com/bootdotdev/learn-web-security/internal/storefront"
)

type Handler struct {
	accountStore      *accounts.Store
	orderStore        *orders.Store
	productStore      *storefront.Store
	apiStore          *Store
	logger            *logging.Logger
	maxProductResults int64
}

type productResponse struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	ImagePath   string `json:"image_path"`
	PriceCents  int64  `json:"price_cents"`
}

type orderResponse struct {
	ID         int64  `json:"id"`
	Status     string `json:"status"`
	TotalCents int64  `json:"total_cents"`
	CreatedAt  string `json:"created_at"`
}

/*
Defining the struct types is just step 1!
Once these shapes look right,
you'll still need to write the logic that converts
your stored Product/Order models into these response types inside each handler function,
and use those converted values in the JSON response instead of the raw stored models.
*/

type integrationOrderResponse struct {
	ID         int64  `json:"id"`
	Status     string `json:"status"`
	TotalCents int64  `json:"total_cents"`
	CreatedAt  string `json:"created_at"`
}

type orderItemResponse struct {
	ProductID   int64  `json:"product_id"`
	ProductName string `json:"product_name"`
	Quantity    int64  `json:"quantity"`
	PriceCents  int64  `json:"price_cents"`
}

func NewHandler(accountStore *accounts.Store, orderStore *orders.Store, productStore *storefront.Store, apiStore *Store, logger *logging.Logger, maxProductResults int) *Handler {
	return &Handler{
		accountStore: accountStore, orderStore: orderStore, productStore: productStore, apiStore: apiStore,
		logger: logger, maxProductResults: int64(maxProductResults),
	}
}

func (handler *Handler) AccountOrders(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAuthentication(responseWriter, request)
	if !ok {
		return
	}
	orders, err := handler.orderStore.ListForUser(request.Context(), current.User.ID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	// Hide sensitive fields acquired from database, for this particular public API handler GET /api/orders.
	var orderResponses []orderResponse
	orderResponses = toOrderResponseList(orders) // Response JSON body has deliberately not mapped all fields to avoid data-leak via public-API
	httpx.RespondWithJSON(responseWriter, http.StatusOK, map[string]any{"orders": orderResponses})
}

// Helper fn to avoid Data-Leak via HTTP Response JSON body
func toOrderResponse(order orders.Order) orderResponse {
	return orderResponse{
		ID:         order.ID,
		Status:     order.Status,
		TotalCents: order.TotalCents,
		CreatedAt:  order.CreatedAt,
	}
}

// Helper fn to avoid Data-Leak via HTTP Response JSON body
func toOrderResponseList(orders []orders.Order) []orderResponse {
	orderResponses := make([]orderResponse, 0, len(orders))
	for _, order := range orders {
		orderResponses = append(orderResponses, toOrderResponse(order))
	}
	return orderResponses
}

func (handler *Handler) Order(responseWriter http.ResponseWriter, request *http.Request) {
	current, ok := handler.requireAuthentication(responseWriter, request)
	if !ok {
		return
	}
	orderID, valid := httpx.ParseSafeInteger(request.PathValue("id"))
	if !valid {
		httpx.RespondWithJSON(responseWriter, http.StatusNotFound, map[string]string{"error": "Order not found"})
		return
	}
	order, found, err := handler.orderStore.FindByID(request.Context(), orderID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !found || order.UserID != current.User.ID {
		httpx.RespondWithJSON(responseWriter, http.StatusNotFound, map[string]string{"error": "Order not found"})
		return
	}
	items, err := handler.orderStore.ListItems(request.Context(), order.ID)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	// Successfully prevent data-leak of sensitive JSON-tags. Mapping to 'orderItemResponse' achieves that.
	itemResponses := make([]orderItemResponse, 0, len(items))
	for _, item := range items {
		itemResponses = append(itemResponses, orderItemResponse{
			ProductID:   item.ProductID,
			ProductName: item.ProductName,
			Quantity:    item.Quantity,
			PriceCents:  item.PriceCents,
		})
	}
	// Successfully prevent Data-Leak
	var orderResp orderResponse
	orderResp = toOrderResponse(order)
	// Exit:
	httpx.RespondWithJSON(responseWriter, http.StatusOK, map[string]any{"order": orderResp, "items": itemResponses})
}

func (handler *Handler) Products(responseWriter http.ResponseWriter, request *http.Request) {
	//products, err := handler.productStore.ListAllProducts(request.Context(), handler.maxProductResults)
	products, err := handler.productStore.ListProducts(request.Context(), handler.maxProductResults)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	// Hide sensitive fields for this public-API, by converting to 'productResponse' type
	var productResponses []productResponse
	productResponses = toProductResponseList(products)
	// Exit handler with JSON:
	httpx.RespondWithJSON(responseWriter, http.StatusOK, map[string]any{"products": productResponses})
}

// Helper fn to avoid Data-Leak via HTTP Response JSON body
func toProductResponse(product storefront.Product) productResponse {
	return productResponse{
		ID:          product.ID,
		Name:        product.Name,
		Description: product.Description,
		ImagePath:   product.ImagePath,
		PriceCents:  product.PriceCents,
	}
}

// Helper fn to avoid Data-Leak via HTTP Response JSON body
func toProductResponseList(products []storefront.Product) []productResponse {
	productResponses := make([]productResponse, 0, len(products))
	for _, product := range products {
		productResponses = append(productResponses, toProductResponse(product))
	}
	return productResponses
}

func (handler *Handler) WarehouseOrders(responseWriter http.ResponseWriter, request *http.Request) {
	apiKey, found, err := handler.apiStore.FindKey(request.Context(), request.Header.Get("X-API-Key"))
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	if !found {
		httpx.RespondWithJSON(responseWriter, http.StatusUnauthorized, map[string]string{"error": "Invalid API key"})
		return
	}
	if apiKey.Scope != "orders:read" {
		httpx.RespondWithJSON(responseWriter, http.StatusForbidden, map[string]string{"error": "API key scope is not allowed"})
		return
	}
	orders, err := handler.orderStore.ListAll(request.Context())
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return
	}
	// Successfully prevent data-leak by not outputting all JSON-tags (some are sensitive) to HTTP Response body.
	responses := make([]integrationOrderResponse, 0, len(orders))
	for _, order := range orders {
		responses = append(responses, integrationOrderResponse{
			ID:         order.ID,
			Status:     order.Status,
			TotalCents: order.TotalCents,
			CreatedAt:  order.CreatedAt,
		})
	}
	httpx.RespondWithJSON(responseWriter, http.StatusOK, map[string]any{
		"integration": "Warehouse Fulfillment Integration",
		"orders":      responses,
	})
}

func (handler *Handler) requireAuthentication(responseWriter http.ResponseWriter, request *http.Request) (accounts.CurrentSession, bool) {
	current, found, err := sessions.Current(request, handler.accountStore)
	if err != nil {
		handler.internalError(responseWriter, request, err)
		return accounts.CurrentSession{}, false
	}
	if !found {
		httpx.RespondWithJSON(responseWriter, http.StatusUnauthorized, map[string]string{"error": "Authentication required"})
		return accounts.CurrentSession{}, false
	}
	return current, true
}

func (handler *Handler) internalError(responseWriter http.ResponseWriter, request *http.Request, err error) {
	_ = handler.logger.Event("unhandled_error", map[string]any{"method": request.Method, "path": request.URL.Path, "message": err.Error()})
	httpx.RespondWithError(responseWriter, http.StatusInternalServerError, err.Error())
}
