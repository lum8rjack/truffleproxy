NAME=truffleproxy
BUILD=go build -ldflags "-s -w" -trimpath

default:
	@ echo "Compiling"
	$(BUILD) -o $(NAME)

clean:
	@ echo "Removing binaries"
	rm -f $(NAME)*

linux:
	@echo "Compiling for Linux x64"
	GOOS=linux GOARCH=amd64 $(BUILD) -o $(NAME)-Linux64

windows:
	@echo "Compiling for Windows x64"
	GOOS=windows GOARCH=amd64 $(BUILD) -o $(NAME)-Windows64.exe

mac:
	@echo "Compiling for Mac x64"
	GOOS=darwin GOARCH=amd64 $(BUILD) -o $(NAME)-Darwin64

m1:
	@echo "Compiling for Mac M1"
	GOOS=darwin GOARCH=arm64 $(BUILD) -o $(NAME)-M1

arm:
	@echo "Compiling for Linux Arm64"
	GOOS=linux GOARCH=arm64 $(BUILD) -o $(NAME)-LinuxArm64
