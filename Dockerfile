FROM golang:1.18.0-alpine3.14 AS build
RUN apk update && apk add git
WORKDIR /src
ENV CGO_ENABLED=0
COPY go.* .
RUN go mod download
COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build \
  go build -o app -ldflags "-X main.GitCommit=${GIT_COMMIT}" .

FROM golang:1.18.0-alpine3.14
RUN apk add --no-cache tzdata
ENV HOME /root
COPY --from=build /src/app /root/app
EXPOSE 8080
CMD ["/root/app"]
