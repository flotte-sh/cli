set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

binary := "flotte"
dist_dir := "dist"
version := env("FLOTTE_VERSION", `git describe --tags --always --dirty 2>/dev/null || echo dev`)
ldflags := '-s -w -X main.version=' + version
default_platforms := "linux/amd64 linux/arm64 linux/arm linux/386 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"
platforms := env("FLOTTE_PLATFORMS", default_platforms)

default:
    @just --list

build:
    mkdir -p "{{ dist_dir }}"
    CGO_ENABLED=0 go build -trimpath -ldflags='{{ ldflags }}' -o "{{ dist_dir }}/{{ binary }}" ./cmd/flotte

build-darwin:
    mkdir -p "{{ dist_dir }}/{{ binary }}_darwin_amd64"
    CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags='{{ ldflags }}' -o "{{ dist_dir }}/{{ binary }}_darwin_amd64/{{ binary }}" ./cmd/flotte

build-darwin-arm64:
    mkdir -p "{{ dist_dir }}/{{ binary }}_darwin_arm64"
    CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags='{{ ldflags }}' -o "{{ dist_dir }}/{{ binary }}_darwin_arm64/{{ binary }}" ./cmd/flotte

build-windows:
    mkdir -p "{{ dist_dir }}/{{ binary }}_windows_amd64"
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags='{{ ldflags }}' -o "{{ dist_dir }}/{{ binary }}_windows_amd64/{{ binary }}.exe" ./cmd/flotte

build-windows-arm64:
    mkdir -p "{{ dist_dir }}/{{ binary }}_windows_arm64"
    CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -trimpath -ldflags='{{ ldflags }}' -o "{{ dist_dir }}/{{ binary }}_windows_arm64/{{ binary }}.exe" ./cmd/flotte

build-all:
    mkdir -p "{{ dist_dir }}"
    for platform in {{ platforms }}; do \
        os="${platform%/*}"; \
        arch="${platform#*/}"; \
        ext=""; \
        if [ "$os" = "windows" ]; then ext=".exe"; fi; \
        output="{{ dist_dir }}/{{ binary }}_${os}_${arch}/{{ binary }}${ext}"; \
        echo "Building $output"; \
        mkdir -p "$(dirname "$output")"; \
        GOARM=""; \
        if [ "$arch" = "arm" ]; then GOARM="GOARM=7"; fi; \
        env CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" $GOARM go build -trimpath -ldflags='{{ ldflags }}' -o "$output" ./cmd/flotte; \
    done

release-bundle: clean build-all
    for platform in {{ platforms }}; do \
        os="${platform%/*}"; \
        arch="${platform#*/}"; \
        name="{{ binary }}_${os}_${arch}"; \
        cp README.md License "{{ dist_dir }}/$name/"; \
        if [ "$os" = "windows" ]; then \
            (cd "{{ dist_dir }}" && zip -q -r "$name.zip" "$name"); \
            (cd "{{ dist_dir }}" && sha256sum "$name.zip" > "$name.zip.sha256"); \
        else \
            tar -C "{{ dist_dir }}" -czf "{{ dist_dir }}/$name.tar.gz" "$name"; \
            (cd "{{ dist_dir }}" && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256"); \
        fi; \
    done

test:
    go test ./...

lint:
    gofmt -l .
    go vet ./...
    staticcheck ./...

clean:
    rm -rf "{{ dist_dir }}"
