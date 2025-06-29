

URL := https://uops.info/instructions.xml

# Name of the file to save
OUTPUT := uops.xml

# Use curl or wget, depending on what’s available
DOWNLOADER := $(shell command -v curl 2>/dev/null || command -v wget 2>/dev/null)

all: $(OUTPUT)

$(OUTPUT):
	@if [ "$(DOWNLOADER)" = "" ]; then \
		echo "Neither curl nor wget found!"; \
		exit 1; \
	fi
	@if [ "$(DOWNLOADER)" = "curl" ]; then \
		echo "Downloading with curl..."; \
		curl -o $(OUTPUT) $(URL); \
	else \
		echo "Downloading with wget..."; \
		wget -O $(OUTPUT) $(URL); \
	fi

clean:
	rm -f $(OUTPUT)
