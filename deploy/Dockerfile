FROM golang:1.25

WORKDIR /app

COPY bin/ /app
COPY deploy/zoneinfo /usr/share/zoneinfo

ENV SERVICE=sso

ENV APP_HOME=/app
ENV GO111MODULE=on
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

RUN ln -snf /usr/share/zoneinfo/Asia/Jakarta /etc/localtime && \
    echo Asia/Jakarta > /etc/timezone && \
    ln -sf /var/www/efs/public/payment/logs /app/logs && \
    ln -sf /var/www/efs/public/payment/logs /app/.logs && \
    chmod +x /app/payment

CMD ["/app/payment"]