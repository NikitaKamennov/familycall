package main

import (
	"context"
	"embed"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"familycall/server/internal/config"
	"familycall/server/internal/database"
	"familycall/server/internal/handlers"
	"familycall/server/internal/turn"
	"familycall/server/internal/websocket"

	"github.com/gin-gonic/gin"
)

import "strconv"

// Версия приложения
const AppVersion = "1.0.0"

// Базовый путь, под которым будет работать приложение за Nginx
const BasePath = "/kamnefon"

// Порт, на котором слушает сам Go-сервер (HTTP, без TLS), Nginx проксирует сюда
const HTTPListenPort = "5080"

// Внешний домен. Для формирования пуш-URL мы прошьём cfg.Domain = ExternalDomainHost + BasePath
const ExternalDomainHost = "bvnt.ru"

//go:embed web/*
var staticFiles embed.FS

//go:embed translations/*.json
var translationsFS embed.FS

// Build timestamp - set at compile time or use current time
// стало:
var buildTimestamp int64
var buildTimestampStr string

func main() {

	if buildTimestampStr != "" {
		if v, err := strconv.ParseInt(buildTimestampStr, 10, 64); err == nil {
			 buildTimestamp = v
		} else {
			 buildTimestamp = time.Now().Unix()
		}
  } else {
		buildTimestamp = time.Now().Unix()
  }

	// Log version and build info
	log.Printf("Family Callbook Server v%s (build: %d)", AppVersion, buildTimestamp)

	// Load configuration
	cfg := config.Load()

	// Принудительно прошьём нужные параметры (без env)
	cfg.HTTPPort = HTTPListenPort
	// HTTPS нам не нужен здесь, TLS делает Nginx
	cfg.HTTPSPort = "0"
	// В cfg.Domain положим домен + путь, чтобы пуш-URL указывали сразу на /kamnefon
	cfg.Domain = ExternalDomainHost + BasePath

	// Initialize database
	db, err := database.Initialize(cfg.DatabasePath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Initialize WebSocket hub
	hub := websocket.NewHub()
	go hub.Run()

	// Initialize TURN server
	turnServer, err := turn.Initialize(cfg.TURNPort, cfg.TURNRealm)
	if err != nil {
		log.Fatalf("Failed to initialize TURN server: %v", err)
	}
	defer turnServer.Close()
	log.Printf("TURN server started on port %d", cfg.TURNPort)

	// Initialize handlers
	h := handlers.New(db, hub, cfg, turnServer, translationsFS)

	// Setup router с учётом BasePath
	router := setupRouter(h, cfg, BasePath)

	// Стартуем обычный HTTP (за Nginx)
	startHTTPServer(router, cfg)
}

func setupRouter(h *handlers.Handlers, cfg *config.Config, basePath string) *gin.Engine {
	if os.Getenv("GIN_MODE") == "" {
		gin.SetMode(gin.ReleaseMode)
	}
	router := gin.Default()

	// Если сервер работает за Nginx, можно доверять прокси (по умолчанию nil = все)
	_ = router.SetTrustedProxies(nil)

	// Middleware: срезаем BasePath на входе (оставляем как было)
	if basePath != "" && basePath != "/" {
		router.Use(func(c *gin.Context) {
			if strings.HasPrefix(c.Request.URL.Path, basePath) {
				c.Request.URL.Path = strings.TrimPrefix(c.Request.URL.Path, basePath)
				if c.Request.URL.Path == "" {
					c.Request.URL.Path = "/"
				}
			}
			c.Next()
		})
	}

	// CORS middleware (оставим как было)
	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	// Public routes (без префикса)
	api := router.Group("/api")
	{
		api.POST("/register", h.Register)
		api.POST("/login", h.Login)
		api.GET("/registration-status", h.CheckRegistrationStatus)
		api.GET("/invite/:uuid", h.GetInvite)
		api.GET("/vapid-public-key", h.GetVAPIDPublicKey)
		api.GET("/turn-config", h.GetTURNConfig)
		api.GET("/translations/:lang", h.GetTranslations)
	}

	// Protected routes (без префикса)
	protected := api.Group("")
	protected.Use(h.AuthMiddleware())
	{
		protected.GET("/me", h.GetMe)
		protected.POST("/users/rename", h.RenameUser)
		protected.GET("/contacts", h.GetContacts)
		protected.POST("/contacts", h.CreateContact)
		protected.DELETE("/contacts/:id", h.DeleteContact)
		protected.GET("/contacts/:contact_id/invite", h.GetInviteForContact)
		protected.GET("/invites/pending", h.GetPendingInvites)
		protected.DELETE("/invites/:id", h.DeleteInvite)
		protected.POST("/invite", h.CreateInvite)
		protected.POST("/invite/:uuid/accept", h.AcceptInvite)
		protected.POST("/call", h.InitiateCall)
		protected.POST("/push/subscribe", h.SubscribePush)
		protected.DELETE("/push/subscribe", h.UnsubscribePush)
		protected.GET("/backup", h.Backup)
		protected.POST("/restore", h.Restore)
	}

	// ДОБАВЛЕНО: Public routes под BasePath (дубли)
	apiBP := router.Group(basePath + "/api")
	{
		apiBP.POST("/register", h.Register)
		apiBP.POST("/login", h.Login)
		apiBP.GET("/registration-status", h.CheckRegistrationStatus)
		apiBP.GET("/invite/:uuid", h.GetInvite)
		apiBP.GET("/vapid-public-key", h.GetVAPIDPublicKey)
		apiBP.GET("/turn-config", h.GetTURNConfig)
		apiBP.GET("/translations/:lang", h.GetTranslations)
	}

	// ДОБАВЛЕНО: Protected routes под BasePath (дубли)
	protectedBP := apiBP.Group("")
	protectedBP.Use(h.AuthMiddleware())
	{
		protectedBP.GET("/me", h.GetMe)
		protectedBP.POST("/users/rename", h.RenameUser)
		protectedBP.GET("/contacts", h.GetContacts)
		protectedBP.POST("/contacts", h.CreateContact)
		protectedBP.DELETE("/contacts/:id", h.DeleteContact)
		protectedBP.GET("/contacts/:contact_id/invite", h.GetInviteForContact)
		protectedBP.GET("/invites/pending", h.GetPendingInvites)
		protectedBP.DELETE("/invites/:id", h.DeleteInvite)
		protectedBP.POST("/invite", h.CreateInvite)
		protectedBP.POST("/invite/:uuid/accept", h.AcceptInvite)
		protectedBP.POST("/call", h.InitiateCall)
		protectedBP.POST("/push/subscribe", h.SubscribePush)
		protectedBP.DELETE("/push/subscribe", h.UnsubscribePush)
		protectedBP.GET("/backup", h.Backup)
		protectedBP.POST("/restore", h.Restore)
	}

	// WebSocket routes
	router.GET("/ws", h.HandleWebSocket)
	// ДОБАВЛЕНО: дубль для BasePath
	router.GET(basePath+"/ws", h.HandleWebSocket)

	// Manifest.json route (ensure correct content-type)
	router.GET("/manifest.json", func(c *gin.Context) {
		fsys, _ := fs.Sub(staticFiles, "web")
		manifestFile, err := fsys.Open("manifest.json")
		if err != nil {
			c.String(http.StatusNotFound, "Manifest not found")
			return
		}
		defer manifestFile.Close()
		stat, _ := manifestFile.Stat()
		c.DataFromReader(http.StatusOK, stat.Size(), "application/manifest+json", manifestFile, nil)
	})

	// Service worker route (ensure correct content-type and inject cache version)
	router.GET("/service-worker.js", func(c *gin.Context) {
		fsys, _ := fs.Sub(staticFiles, "web")
		swFile, err := fsys.Open("service-worker.js")
		if err != nil {
			c.String(http.StatusNotFound, "Service worker not found")
			return
		}
		defer swFile.Close()

		// Read the service worker content
		swContent, err := io.ReadAll(swFile)
		if err != nil {
			c.String(http.StatusInternalServerError, "Failed to read service worker")
			return
		}

		// Inject build timestamp into cache name
		swStr := string(swContent)
		cacheName := fmt.Sprintf("familycall-v3-%d", buildTimestamp)
		swStr = strings.ReplaceAll(swStr, `const CACHE_NAME = 'familycall-v3';`, fmt.Sprintf(`const CACHE_NAME = '%s';`, cacheName))
		c.Header("Content-Type", "application/javascript; charset=utf-8")
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		c.String(http.StatusOK, swStr)
	})

	// Public invite page route (for sharing invite links)
	router.GET("/invite/:uuid", func(c *gin.Context) {
		serveIndexHTML(c, basePath)
	})
	router.GET("/call", func(c *gin.Context) {
		serveIndexHTML(c, basePath)
	})

	// Root route
	router.GET("/", func(c *gin.Context) {
		serveIndexHTML(c, basePath)
	})

	// Serve static files (PWA)
	router.NoRoute(serveStaticFiles(basePath))

	return router
}

// serveIndexHTML serves index.html with versioned script tags and BasePath injection
func serveIndexHTML(c *gin.Context, basePath string) {
	fsys, _ := fs.Sub(staticFiles, "web")
	indexFile, err := fsys.Open("index.html")
	if err != nil {
		c.String(http.StatusNotFound, "Not found")
		return
	}
	defer indexFile.Close()

	// Read the HTML content
	htmlContent, err := io.ReadAll(indexFile)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to read index.html")
		return
	}

	// Generate version string (version + timestamp)
	version := fmt.Sprintf("%s-%d", AppVersion, buildTimestamp)

	// Replace script and stylesheet tags with versioned URLs and BasePath
	htmlStr := string(htmlContent)

	prefix := basePath
	if prefix == "/" {
		prefix = ""
	}

	// Префикс статических ресурсов
	htmlStr = strings.ReplaceAll(htmlStr, `src="/app.js"`, fmt.Sprintf(`src="%s/app.js?v=%s"`, prefix, version))
	htmlStr = strings.ReplaceAll(htmlStr, `href="/styles.css"`, fmt.Sprintf(`href="%s/styles.css?v=%s"`, prefix, version))

	// Префикс PWA-ресурсов
	htmlStr = strings.ReplaceAll(htmlStr, `href="/service-worker.js"`, fmt.Sprintf(`href="%s/service-worker.js?v=%s"`, prefix, version))
	htmlStr = strings.ReplaceAll(htmlStr, `src="/service-worker.js"`, fmt.Sprintf(`src="%s/service-worker.js?v=%s"`, prefix, version))
	htmlStr = strings.ReplaceAll(htmlStr, `href="/manifest.json"`, fmt.Sprintf(`href="%s/manifest.json?v=%s"`, prefix, version))

	// Инъекция мини-скрипта: переписываем fetch('/api'), WebSocket('/ws') и SW.register('/service-worker.js')
	injector := fmt.Sprintf(`
<script>
(function(basePath) {
  try {
    // Сохраним в глобальную переменную
    window.__BASE_PATH__ = basePath;

    // Переписывание fetch для "/api"
    var origFetch = window.fetch;
    window.fetch = function(input, init) {
      try {
        var url = input;
        if (typeof url === 'string') {
          if (url === '/api' || url.startsWith('/api/')) {
            url = basePath + url;
          }
        } else if (url && url.url) { // Request объект
          var u = url.url;
          if (typeof u === 'string' && (u === '/api' || u.startsWith('/api/'))) {
            url = new Request(basePath + u, url);
          }
        }
        return origFetch(url, init);
      } catch(e) {
        return origFetch(input, init);
      }
    };

    // Переписывание WebSocket для "/ws"
    var OrigWebSocket = window.WebSocket;
    window.WebSocket = function(url, protocols) {
      try {
        if (typeof url === 'string') {
          if (url.startsWith('/')) {
            // Абсолютный путь от корня
            if (url === '/ws' || url.startsWith('/ws')) {
              url = basePath + url;
            }
          } else if (url.startsWith('ws://') || url.startsWith('wss://')) {
            // Абсолютный URL: если это тот же хост и путь начинается с /ws, префиксуем
            var a = document.createElement('a');
            a.href = url.replace(/^ws/,'http'); // для корректного парсинга
            if (a.host === window.location.host && (a.pathname === '/ws' || a.pathname.startsWith('/ws'))) {
              var proto = (window.location.protocol === 'https:') ? 'wss:' : 'ws:';
              url = proto + '//' + a.host + basePath + a.pathname + (a.search || '');
            }
          } else {
            // относительный путь - оставляем как есть
          }
        }
      } catch(e) {}
      return new OrigWebSocket(url, protocols);
    };

    // Переписывание регистрации Service Worker
    if (navigator.serviceWorker && navigator.serviceWorker.register) {
      var origRegister = navigator.serviceWorker.register.bind(navigator.serviceWorker);
      navigator.serviceWorker.register = function(swUrl, opts) {
        try {
          if (typeof swUrl === 'string') {
            if (swUrl.startsWith('/')) {
              swUrl = basePath + swUrl;
            }
          }
          if (!opts || !opts.scope) {
            opts = Object.assign({}, opts, { scope: basePath + '/' });
          }
        } catch(e) {}
        return origRegister(swUrl, opts);
      };
    }
  } catch(e) {}
})(%q);
</script>`, prefix)

	// Вставим инъекцию перед </head> (если head есть)
	if strings.Contains(htmlStr, "</head>") {
		htmlStr = strings.Replace(htmlStr, "</head>", injector+"\n</head>", 1)
	} else {
		// fallback: добавим в начало
		htmlStr = injector + "\n" + htmlStr
	}

	// Inject version into HTML for display
	htmlStr = strings.ReplaceAll(htmlStr, `<h2>Family Callbook</h2>`, fmt.Sprintf(`<h2>Family Callbook</h2><p class="app-version">v%s</p>`, AppVersion))
	htmlStr = strings.ReplaceAll(htmlStr, `<h1>Family Callbook</h1>`, fmt.Sprintf(`<h1>Family Callbook</h1><p class="app-version">v%s</p>`, AppVersion))

	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Header("Pragma", "no-cache")
	c.Header("Expires", "0")
	c.String(http.StatusOK, htmlStr)
}

// serveStaticFiles serves embedded static files
func serveStaticFiles(basePath string) gin.HandlerFunc {
	// Get the subdirectory
	fsys, err := fs.Sub(staticFiles, "web")
	if err != nil {
		panic("Failed to create sub filesystem: " + err.Error())
	}

	fileServer := http.FileServer(http.FS(fsys))

	return func(c *gin.Context) {
		path := c.Request.URL.Path

		// Skip API routes, WebSocket
		if strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/ws") {
			c.Next()
			return
		}

		// Remove leading slash
		path = strings.TrimPrefix(path, "/")

		// Check if file exists
		_, err := fsys.Open(path)
		if err != nil {
			// File doesn't exist, serve index.html for SPA routing
			serveIndexHTML(c, basePath)
			return
		}

		// If serving index.html, use versioned/injected version
		if path == "index.html" {
			serveIndexHTML(c, basePath)
			return
		}

		// Set proper content type and cache headers
		ext := filepath.Ext(path)
		switch ext {
		case ".html":
			c.Header("Content-Type", "text/html; charset=utf-8")
			c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		case ".css":
			c.Header("Content-Type", "text/css; charset=utf-8")
			c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		case ".js":
			c.Header("Content-Type", "application/javascript; charset=utf-8")
			c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		case ".json":
			c.Header("Content-Type", "application/json; charset=utf-8")
		case ".png":
			c.Header("Content-Type", "image/png")
		case ".jpg", ".jpeg":
			c.Header("Content-Type", "image/jpeg")
		case ".svg":
			c.Header("Content-Type", "image/svg+xml")
		case ".ico":
			c.Header("Content-Type", "image/x-icon")
		}

		fileServer.ServeHTTP(c.Writer, c.Request)
		c.Abort()
	}
}

// Упрощённый HTTP-сервер (без TLS), за Nginx
func startHTTPServer(router *gin.Engine, cfg *config.Config) {
	srv := &http.Server{
		Addr:         ":" + cfg.HTTPPort,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
		// ErrorLog: можно задать при желании
	}

	log.Printf("HTTP server (behind NGINX) starting on port %s, BasePath=%s", cfg.HTTPPort, BasePath)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Failed to start HTTP server: %v", err)
	}
}

// Оставим normalizeDomain и пр. не нужны — autocert отключён
// Но оставим заглушки для совместимости, если потребуется контекст
// (не используются сейчас, можно удалить при желании)

type tlsErrorFilter struct {
	writer io.Writer
}

func (f *tlsErrorFilter) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func normalizeDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimPrefix(domain, "www.")
	return domain
}

// Пустой контекст, чтобы не таскать импорт зря
var _ = context.Background