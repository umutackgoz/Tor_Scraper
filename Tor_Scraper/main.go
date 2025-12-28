package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
	"golang.org/x/net/proxy"
	"gopkg.in/yaml.v3"
)

type TargetList struct {
	URLs []string `yaml:"urls"`
}

const (
	defaultTargetsFile = "targets.yaml"
	defaultOutputDir   = "output"
	defaultUserAgent   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
)

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	targetsPath := defaultTargetsFile
	if len(os.Args) > 1 {
		targetsPath = os.Args[1]
	}

	targets, err := loadTargets(targetsPath)
	if err != nil {
		log.Fatalf("[FATAL] Target listesi okunamadı: %v", err)
	}
	if len(targets.URLs) == 0 {
		log.Fatalf("[FATAL] %s içinde taranacak URL bulunamadı", targetsPath)
	}

	if err := os.MkdirAll(defaultOutputDir, 0o755); err != nil {
		log.Fatalf("[FATAL] Çıktı klasörü oluşturulamadı: %v", err)
	}

	client, err := newTorHTTPClient("127.0.0.1:9150", 60*time.Second)
	if err != nil {
		log.Fatalf("[FATAL] Tor HTTP istemcisi oluşturulamadı: %v", err)
	}

	log.Printf("[INFO] Tor IP kontrolü yapılıyor...")
	if err := checkTorIP(client); err != nil {
		log.Printf("[WARN] IP kontrolü başarısız: %v", err)
	} else {
		log.Printf("[INFO] IP kontrolü tamamlandı - Tor IP'si kullanılıyor")
	}

	var wg sync.WaitGroup
	urls := make([]string, 0, len(targets.URLs))

	for _, rawURL := range targets.URLs {
		url := strings.TrimSpace(rawURL)
		if url == "" {
			continue
		}
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			url = "http://" + url
		}
		urls = append(urls, url)
	}

	log.Printf("[INFO] %d URL paralel olarak taranacak...", len(urls))

	// Her URL için goroutine başlat
	for _, url := range urls {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			processURL(client, u)
		}(url)
	}

	wg.Wait()
	log.Printf("[INFO] Tüm taramalar tamamlandı!")
}

func loadTargets(path string) (*TargetList, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var tl TargetList
	if err := yaml.Unmarshal(data, &tl); err != nil {
		return nil, err
	}
	return &tl, nil
}

func newTorHTTPClient(proxyAddr string, timeout time.Duration) (*http.Client, error) {
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("SOCKS5 proxy oluşturulamadı: %w", err)
	}

	// context destekli Dial fonksiyonu sağlama
	netDialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dialer.Dial(network, addr)
		if err != nil {
			return nil, err
		}
		_ = netDialer
		return conn, nil
	}

	tr := &http.Transport{
		DialContext:         dialContext,
		DisableKeepAlives:   false,
		MaxIdleConns:        10,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 30 * time.Second,
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}
	return client, nil
}

func scanURL(client *http.Client, url string) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("istek oluşturulamadı: %w", err)
	}

	req.Header.Set("User-Agent", defaultUserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	resp, err := client.Do(req)
	if err != nil {
		if os.IsTimeout(err) {
			return fmt.Errorf("TIMEOUT")
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return fmt.Errorf("TIMEOUT")
		}
		return fmt.Errorf("ERROR")
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return fmt.Errorf("ERROR")
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024)) // maks 5MB
	if err != nil {
		return fmt.Errorf("body okunamadı: %w", err)
	}

	filename := sanitizeFilename(url) + ".html"
	outputPath := filepath.Join(defaultOutputDir, filename)

	if err := os.WriteFile(outputPath, body, 0o644); err != nil {
		return fmt.Errorf("çıktı yazılamadı: %w", err)
	}

	return nil
}

// URL'i geçerli bir dosya adına çevirmek için
func sanitizeFilename(url string) string {
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")

	// Path ve query'leri dosya adına dönüştür
	url = strings.ReplaceAll(url, "/", "_")
	url = strings.ReplaceAll(url, "?", "_")
	url = strings.ReplaceAll(url, "&", "_")
	url = strings.ReplaceAll(url, "=", "_")
	url = strings.ReplaceAll(url, ":", "_")

	if len(url) == 0 {
		return "index"
	}
	return url
}

func processURL(client *http.Client, url string) {
	log.Printf("[INFO] Scanning: %s", url)
	start := time.Now()
	if err := scanURL(client, url); err != nil {
		log.Printf("[ERR]  Scanning: %s -> %s (%.1fs)", url, err.Error(), time.Since(start).Seconds())
	} else {
		log.Printf("[INFO] Scanning: %s -> SUCCESS (%.1fs)", url, time.Since(start).Seconds())
		if err := takeScreenshot(url); err != nil {
			log.Printf("[WARN] Screenshot alınamadı: %s -> %v", url, err)
		} else {
			log.Printf("[INFO] Screenshot kaydedildi: %s", url)
		}
	}
}

func takeScreenshot(url string) error {
	// Chrome'un SOCKS5 proxy ile çalışması için özel ayarlar
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ProxyServer("socks5://127.0.0.1:9150"),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.UserAgent(defaultUserAgent),
		chromedp.WindowSize(1920, 1080),
	)

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancelAlloc()

	// Parse error'ları bastırmak için sessiz log fonksiyonu
	ctx, cancelCtx := chromedp.NewContext(allocCtx, chromedp.WithLogf(func(format string, v ...interface{}) {

	}))
	defer cancelCtx()

	ctx, cancelTimeout := context.WithTimeout(ctx, 90*time.Second)
	defer cancelTimeout()

	var buf []byte

	err := chromedp.Run(ctx,
		chromedp.Navigate(url),
		chromedp.WaitVisible("body", chromedp.ByQuery),
		chromedp.Sleep(3*time.Second),
		chromedp.Evaluate(`window.scrollTo(0, document.body.scrollHeight)`, nil),
		chromedp.Sleep(2*time.Second),
		chromedp.Evaluate(`window.scrollTo(0, 0)`, nil),
		chromedp.Sleep(1*time.Second),
		chromedp.FullScreenshot(&buf, 100),
	)

	if err != nil {
		return fmt.Errorf("screenshot hatası: %w", err)
	}

	filename := "screenshot_" + sanitizeFilename(url) + ".png"
	outputPath := filepath.Join(defaultOutputDir, filename)

	if len(buf) == 0 {
		return fmt.Errorf("screenshot boş")
	}

	if err := os.WriteFile(outputPath, buf, 0o644); err != nil {
		return fmt.Errorf("screenshot kaydedilemedi: %w", err)
	}

	return nil
}

// Tor IP'si kullanıldığını doğrulamak için check.torproject.org'a istek atar.
func checkTorIP(client *http.Client) error {
	req, err := http.NewRequest(http.MethodGet, "https://check.torproject.org/api/ip", nil)
	if err != nil {
		return fmt.Errorf("istek oluşturulamadı: %w", err)
	}

	req.Header.Set("User-Agent", defaultUserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("IP kontrolü başarısız: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		return fmt.Errorf("yanıt okunamadı: %w", err)
	}

	bodyStr := string(body)
	if strings.Contains(bodyStr, "IsTor") || strings.Contains(bodyStr, "tor") {
		log.Printf("[INFO] Tor IP kontrolü yanıtı: %s", strings.TrimSpace(bodyStr))
		return nil
	}

	// Alternatif olarak HTML sayfasını kontrol et
	req2, _ := http.NewRequest(http.MethodGet, "https://check.torproject.org/", nil)
	req2.Header.Set("User-Agent", defaultUserAgent)
	resp2, err := client.Do(req2)
	if err == nil {
		defer resp2.Body.Close()
		body2, _ := io.ReadAll(io.LimitReader(resp2.Body, 8192))
		body2Str := string(body2)
		if strings.Contains(strings.ToLower(body2Str), "congratulations") || strings.Contains(strings.ToLower(body2Str), "using tor") {
			log.Printf("[INFO] Tor IP kontrolü başarılı - Tor kullanılıyor")
			return nil
		}
	}

	log.Printf("[INFO] IP kontrolü yanıtı: %s", strings.TrimSpace(bodyStr))
	return nil
}
