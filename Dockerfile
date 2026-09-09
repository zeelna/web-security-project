FROM golang:1.27.0-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -trimpath -o /out/bearly-secure ./cmd/server
RUN CGO_ENABLED=0 go build -trimpath -o /out/bearly-attacker-lab ./cmd/attackerlab


FROM alpine:3.22

RUN apk add --no-cache ca-certificates \
    && addgroup -S bearly \
    && adduser -S -G bearly bearly \
    && mkdir -p /app/data/uploads

WORKDIR /app

COPY --from=build --chown=bearly:bearly /out/bearly-secure ./bearly-secure
COPY --from=build --chown=bearly:bearly /out/bearly-attacker-lab ./bearly-attacker-lab
COPY --chown=bearly:bearly attacker-lab ./attacker-lab
COPY --chown=bearly:bearly web ./web
COPY --chown=bearly:bearly \
    data/uploads/mystery-shack-tax-exemption.pdf \
    ./data/uploads/mystery-shack-tax-exemption.pdf

RUN chown bearly:bearly ./data

USER bearly

CMD ["./bearly-secure"]
