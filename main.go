package main

import (
    "embed"
    "io/fs"
    "context"
    "crypto/x509"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "strconv"
    "os"
    "time"
    "html/template"
    "sort"

    "github.com/boltdb/bolt"
    "github.com/gin-contrib/sessions"
    "github.com/gin-contrib/sessions/cookie"
	"github.com/gin-contrib/multitemplate"
	"github.com/gin-gonic/gin"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
    "github.com/dustin/go-humanize"


    lnrpc "simple-lnwallet-go/lnrpc"
)

var db *bolt.DB

type Node struct {
    Alias       string `json:"alias"`
    Address     string `json:"address"`
    MacaroonHex string `json:"macaroon_hex"`
    TLSCertHex  string `json:"tls_cert_hex"`
}

type ChannelItem struct {
    Alias        string
    Capacity     int64
    LocalBalance int64
    ChanId       uint64  // novo campo para identificar o canal
}

type ChannelDetail struct {
    Alias    string
    ChanId   uint64
    Capacity int64
    Node1Policy *lnrpc.RoutingPolicy
    Node2Policy *lnrpc.RoutingPolicy
}

type macaroonCredential struct {
    macaroon string
}

func (m macaroonCredential) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
    return map[string]string{"macaroon": m.macaroon}, nil
}

func (m macaroonCredential) RequireTransportSecurity() bool {
    return true
}

//go:embed templates/*
var templatesFS embed.FS

//go:embed static/*
var staticFS embed.FS

func main() {
    // Inicializar banco de dados BoltDB
    var err error
    db, err = bolt.Open("nodes.db", 0600, nil)
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    // Criar tabela de nodes se não existir
    db.Update(func(tx *bolt.Tx) error {
        _, err := tx.CreateBucketIfNotExists([]byte("Nodes"))
        return err
    })

    // Configurar servidor web
	gin.SetMode(gin.ReleaseMode)
    router := gin.Default()
    store := cookie.NewStore([]byte("pxDh5vjqcSfmZuKIbVSgBwmAlzWyj85dWXwOVJysg5s="))
    store.Options(sessions.Options{
        Path:     "/",
        MaxAge:   3600,
        HttpOnly: true,
        Secure:   false, // use false se estiver em HTTP
        SameSite: http.SameSiteLaxMode,
    })
    router.Use(sessions.Sessions("session", store))
    router.Use(func(c *gin.Context) {
        log.Printf("📍 Rota acessada: %s %s", c.Request.Method, c.Request.URL.Path)
        c.Next()
    })

    // Em vez de router.LoadHTMLGlob, use:
    router.HTMLRender = createRenderer()
    log.Println("✅ Templates carregados com sucesso!")
    
    staticContent, err := fs.Sub(staticFS, "static")
    if err != nil {
        log.Fatal(err)
    }
    router.StaticFS("/static", http.FS(staticContent))
    
    router.GET("/", indexHandler)
    router.POST("/", saveNodeHandler)
    router.GET("/dashboard", dashboardHandler)
    router.GET("/invoice", invoiceHandler)
    router.POST("/invoice", createInvoiceHandler)
    router.GET("/pay", payHandler)
    router.POST("/pay", payInvoiceHandler)
    router.GET("/channels", listChannelsHandler)
    router.GET("/channels/:chanPoint", showChannelHandler)
    
    log.Printf("🚀 Servidor iniciando na porta :35671")
    router.Run(":35671")
}
func getNodeByAddress(address string) (Node, error) {
    var node Node
    err := db.View(func(tx *bolt.Tx) error {
        b := tx.Bucket([]byte("Nodes"))
        v := b.Get([]byte(address))
        if v == nil {
            return fmt.Errorf("node not found")
        }
        return json.Unmarshal(v, &node)
    })
    return node, err
}
func createRenderer() multitemplate.Renderer {
    r := multitemplate.NewRenderer()
    funcMap := template.FuncMap{
        "toBTC": func(value interface{}) string {
            var sats int64
            switch v := value.(type) {
            case int:
                sats = int64(v)
            case int64:
                sats = v
            case uint64:
                sats = int64(v)
            default:
                return fmt.Sprintf("%v", v)
            }
            btc := float64(sats) / 1e8
            return fmt.Sprintf("%.8f", btc)
        },
        "formatSat": func(value interface{}) string {
            switch v := value.(type) {
            case int:
                return humanize.Comma(int64(v))
            case int64:
                return humanize.Comma(v)
            case uint64:
                return humanize.Comma(int64(v))
            default:
                return fmt.Sprintf("%v", v)
            }
        },
        "formatTimestamp": func(ts interface{}) string {
        // Supondo que ts seja um número representando Unix timestamp em segundos
            if t, ok := ts.(uint32); ok {
                return time.Unix(int64(t), 0).Format("02.01.2006 15:04:05")
            }
            return fmt.Sprintf("%v", ts)
        },
    }

    // 1) Carregamos "base.html" que agora tem {{ define "base" }}
    baseTmpl := template.Must(template.New("base").
        Funcs(funcMap).
        ParseFS(templatesFS, "templates/base.html"))

    // 2) Mapeamos cada página ao seu arquivo
    pages := map[string]string{
        "index":     "templates/index.html",
        "dashboard": "templates/dashboard.html",
        "invoice":   "templates/invoice.html",
        "pay":       "templates/pay.html",
        "channels":  "templates/channels.html",
        "channel_detail": "templates/channel_detail.html",
    }

    // 3) Para cada página, clonamos o base e parseamos o arquivo específico
    for name, page := range pages {
        tmpl := template.Must(baseTmpl.Clone())
        tmpl = template.Must(tmpl.ParseFS(templatesFS, page))
        
        // Adiciona ao multitemplate com o nome da rota (ex: "index")
        r.Add(name, tmpl)
    }

    return r
}



// Conectar ao node LND via gRPC
func connectLND(address, macaroonHex, tlsCertHex string) (lnrpc.LightningClient, error) {
    // Configurar ciphers (se necessário)
    os.Setenv("GRPC_SSL_CIPHER_SUITES", "HIGH+ECDSA")

    // Converter TLS de HEX para bytes
    tlsCertBytes, err := hex.DecodeString(tlsCertHex)
    if err != nil {
        return nil, fmt.Errorf("erro ao decodificar TLS cert HEX: %v", err)
    }

    // Criar pool de certificados e adicionar o certificado decodificado
    roots := x509.NewCertPool()
    if ok := roots.AppendCertsFromPEM(tlsCertBytes); !ok {
        return nil, fmt.Errorf("falha ao adicionar o certificado TLS")
    }

    // Criar credenciais TLS usando o CertPool; "localhost" é usado para override do nome do host.
    transportCreds := credentials.NewClientTLSFromCert(roots, "localhost")

    // Criar credenciais de autenticação com macaroon
    macCreds := macaroonCredential{macaroon: macaroonHex}

    // Configurar opções do canal gRPC; a opção "grpc.ssl_target_name_override" pode ser passada via WithAuthority ou WithDialer se necessário.
    opts := []grpc.DialOption{
        grpc.WithTransportCredentials(transportCreds),
        grpc.WithPerRPCCredentials(macCreds),
        grpc.WithDefaultCallOptions(),
    }

    // Criar canal gRPC seguro
    conn, err := grpc.Dial(address, opts...)
    if err != nil {
        return nil, fmt.Errorf("erro ao conectar ao LND: %v", err)
    }

    client := lnrpc.NewLightningClient(conn)

    // Testar a conexão com GetInfo usando um timeout
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    _, err = client.GetInfo(ctx, &lnrpc.GetInfoRequest{})
    if err != nil {
        return nil, fmt.Errorf("erro ao autenticar no LND: %v", err)
    }

    return client, nil
}

// Página inicial
func indexHandler(c *gin.Context) {
    
    nodes := getNodes()
    log.Println("🔍 Acessando página inicial...")

    c.HTML(http.StatusOK, "index", gin.H{
        "title": "Lightning Wallet",
        "Nodes": nodes,
    })
}


// Salvar node no banco
func saveNodeHandler(c *gin.Context) {
    node := Node{
        Address:     c.PostForm("node_address"),
        MacaroonHex: c.PostForm("macaroon_hex"),
        TLSCertHex:  c.PostForm("tls_cert_hex"),
    }

    client, err := connectLND(node.Address, node.MacaroonHex, node.TLSCertHex)
    if err != nil {
        c.HTML(http.StatusOK, "index", gin.H{
            "title": "Lightning Wallet",
            "ErrorMessage": err.Error(),
            "Nodes": getNodes(),
        })
        return
    }

    info, _ := client.GetInfo(context.Background(), &lnrpc.GetInfoRequest{})
    node.Alias = info.Alias

    err = db.Update(func(tx *bolt.Tx) error {
        b := tx.Bucket([]byte("Nodes"))
        nodeJSON, _ := json.Marshal(node)
        fmt.Println("🔹 Salvando Node:", node)
        return b.Put([]byte(node.Address), nodeJSON)
    })

    if err != nil {
        fmt.Println("❌ Erro ao salvar node:", err)
    }

    // Salvar node no banco (no saveNodeHandler)
    session := sessions.Default(c)
    session.Set("node_address", node.Address)
    err = session.Save()
    if err != nil {
        log.Printf("Erro ao salvar a sessão: %v", err)
    }
    c.Redirect(http.StatusFound, "/dashboard")

}

// Buscar nodes cadastrados
func getNodes() []Node {
    var nodes []Node
    err := db.View(func(tx *bolt.Tx) error {
        b := tx.Bucket([]byte("Nodes"))
        return b.ForEach(func(k, v []byte) error {
            var node Node
            json.Unmarshal(v, &node)
            nodes = append(nodes, node)
            fmt.Println("📡 Node encontrado:", node)
            return nil
        })
    })

    if err != nil {
        fmt.Println("❌ Erro ao buscar nodes:", err)
    }

    return nodes
}

// Dashboard
func dashboardHandler(c *gin.Context) {
    session := sessions.Default(c)
    addr := session.Get("node_address")
    if addr == nil {
        c.Redirect(http.StatusFound, "/")
        return
    }
    node, err := getNodeByAddress(addr.(string))
    if err != nil {
        c.String(http.StatusInternalServerError, "Erro ao recuperar node: %v", err)
        return
    }

    client, err := connectLND(node.Address, node.MacaroonHex, node.TLSCertHex)
    if err != nil {
        c.String(http.StatusInternalServerError, "Erro ao conectar ao LND: %v", err)
        return
    }
    info, _ := client.GetInfo(context.Background(), &lnrpc.GetInfoRequest{})
    balance, _ := client.WalletBalance(context.Background(), &lnrpc.WalletBalanceRequest{})
    channelBalance, _ := client.ChannelBalance(context.Background(), &lnrpc.ChannelBalanceRequest{})

    c.HTML(http.StatusOK, "dashboard", gin.H{
        "NodeInfo":       info,
        "Balance":        balance,
        "ChannelBalance": channelBalance,
        "SyncedToChain":  "✅",
        "SyncedToGraph":  "✅",
    })
}

// Criar invoice
func createInvoiceHandler(c *gin.Context) {
    session := sessions.Default(c)
    addrI := session.Get("node_address")
    if addrI == nil {
        c.Redirect(http.StatusFound, "/")
        return
    }
    addr := addrI.(string)
    // Recupera o node completo do banco
    node, err := getNodeByAddress(addr)
    if err != nil {
        c.String(http.StatusInternalServerError, "Erro ao recuperar node: %v", err)
        return
    }

    client, err := connectLND(node.Address, node.MacaroonHex, node.TLSCertHex)
    if err != nil {
        c.String(http.StatusInternalServerError, "Erro ao conectar ao LND: %v", err)
        return
    }

    if c.Request.Method == "POST" {
        amount, err := strconv.ParseInt(c.PostForm("amount"), 10, 64)
        if err != nil {
            c.String(http.StatusBadRequest, "Valor inválido para amount")
            return
        }
        memo := c.PostForm("memo")

        req := &lnrpc.Invoice{
            Value: amount,
            Memo:  memo,
        }

        resp, err := client.AddInvoice(context.Background(), req)
        if err != nil {
            c.String(http.StatusInternalServerError, "Erro ao criar fatura: %v", err)
            return
        }

        c.HTML(http.StatusOK, "invoice", gin.H{"Invoice": resp.PaymentRequest})
    } else {
        c.HTML(http.StatusOK, "invoice", nil)
    }
}

// Pagar invoice
func payInvoiceHandler(c *gin.Context) {
    session := sessions.Default(c)
    addrI := session.Get("node_address")
    if addrI == nil {
        c.Redirect(http.StatusFound, "/")
        return
    }
    addr := addrI.(string)
    // Recupera o node completo do banco
    node, err := getNodeByAddress(addr)
    if err != nil {
        c.String(http.StatusInternalServerError, "Erro ao recuperar node: %v", err)
        return
    }

    client, err := connectLND(node.Address, node.MacaroonHex, node.TLSCertHex)
    if err != nil {
        c.String(http.StatusInternalServerError, "Erro ao conectar ao LND: %v", err)
        return
    }

    if c.Request.Method == "POST" {
        paymentRequest := c.PostForm("payment_request")

        req := &lnrpc.SendRequest{
            PaymentRequest: paymentRequest,
        }

        resp, err := client.SendPaymentSync(context.Background(), req)
        if err != nil {
            c.HTML(http.StatusOK, "pay", gin.H{
                "ErrorMessage": fmt.Sprintf("Erro ao pagar fatura: %v", err),
            })
            return
        }

        // Após sucesso no pagamento:
        paymentHashHex := hex.EncodeToString(resp.PaymentHash)
        totalAmt := resp.PaymentRoute.TotalAmt

        resultData := map[string]interface{}{
            "message":   "Pagamento realizado com sucesso!",
            "hash":      paymentHashHex,
            "total_amt": totalAmt,
        }

        c.HTML(http.StatusOK, "pay", gin.H{"result": resultData})
    } else {
        c.HTML(http.StatusOK, "pay", nil)
    }
}

// Exibir a página de Invoice
func invoiceHandler(c *gin.Context) {
    c.HTML(http.StatusOK, "invoice", nil)
}

// Exibir a página de Pagamento
func payHandler(c *gin.Context) {
    session := sessions.Default(c)
    if session.Get("node_address") == nil {
        c.Redirect(http.StatusFound, "/")
        return
    }
    c.HTML(http.StatusOK, "pay", nil)
}
func listChannelsHandler(c *gin.Context) {
    session := sessions.Default(c)
    addrI := session.Get("node_address")
    if addrI == nil {
        c.Redirect(http.StatusFound, "/")
        return
    }
    addr := addrI.(string)
    // Recupera o node do banco
    node, err := getNodeByAddress(addr)
    if err != nil {
        c.String(http.StatusInternalServerError, "Erro ao recuperar node: %v", err)
        return
    }
    client, err := connectLND(node.Address, node.MacaroonHex, node.TLSCertHex)
    if err != nil {
        c.String(http.StatusInternalServerError, "Erro ao conectar ao LND: %v", err)
        return
    }
    // Chama o ListChannels para obter os canais abertos
    channelsResp, err := client.ListChannels(context.Background(), &lnrpc.ListChannelsRequest{})
    if err != nil {
        c.String(http.StatusInternalServerError, "Erro ao listar canais: %v", err)
        return
    }

    // Para cada canal, consulte o alias do nó remoto
    var channelItems []ChannelItem
    for _, channel := range channelsResp.Channels {
        // Obter o alias do nó remoto usando GetNodeInfo
        nodeInfo, err := client.GetNodeInfo(context.Background(), &lnrpc.NodeInfoRequest{
            PubKey: channel.RemotePubkey,
        })
        var alias string
        if err != nil || nodeInfo.Node == nil {
            alias = channel.RemotePubkey // se erro, usa o pubkey como fallback
        } else {
            alias = nodeInfo.Node.Alias
        }

        channelItems = append(channelItems, ChannelItem{
            Alias:        alias,
            Capacity:     channel.Capacity,
            LocalBalance: channel.LocalBalance,
            ChanId:       channel.ChanId,
        })
    }
    sort.Slice(channelItems, func(i, j int) bool {
        return channelItems[i].LocalBalance < channelItems[j].LocalBalance
    })
    c.HTML(http.StatusOK, "channels", gin.H{
        "Channels": channelItems,
        "title":    "Canais do Node",
    })
}

func showChannelHandler(c *gin.Context) {
    chanIdStr := c.Param("chanPoint")
    chanId, err := strconv.ParseUint(chanIdStr, 10, 64)
    if err != nil {
        c.String(http.StatusBadRequest, "ID de canal inválido: %v", err)
        return
    }

    session := sessions.Default(c)
    addrI := session.Get("node_address")
    if addrI == nil {
        c.Redirect(http.StatusFound, "/")
        return
    }
    addr := addrI.(string)

    node, err := getNodeByAddress(addr)
    if err != nil {
        c.String(http.StatusInternalServerError, "Erro ao recuperar node: %v", err)
        return
    }
    client, err := connectLND(node.Address, node.MacaroonHex, node.TLSCertHex)
    if err != nil {
        c.String(http.StatusInternalServerError, "Erro ao conectar ao LND: %v", err)
        return
    }
    
    // Obtém as informações do canal (objeto do tipo *lnrpc.ChannelEdge)
    chanInfo, err := client.GetChanInfo(context.Background(), &lnrpc.ChanInfoRequest{
        ChanId: chanId,
    })
    if err != nil {
        c.String(http.StatusInternalServerError, "Erro ao recuperar dados do canal: %v", err)
        return
    }
    
    // Para exibir o alias, buscamos as informações de um dos nós participantes.
    // Aqui usamos o campo Node2Pub (substitua por Node1Pub se for o caso)
    var alias string
    nodeInfo, err := client.GetNodeInfo(context.Background(), &lnrpc.NodeInfoRequest{
        PubKey: chanInfo.Node2Pub,
    })
    if err != nil || nodeInfo.Node == nil {
        alias = chanInfo.Node2Pub
    } else {
        alias = nodeInfo.Node.Alias
    }
    
    detail := ChannelDetail{
        Alias:    alias,
        ChanId:   chanInfo.ChannelId,   // acesso direto ao campo
        Capacity: chanInfo.Capacity,  // acesso direto ao campo
        Node1Policy: chanInfo.Node1Policy,
        Node2Policy: chanInfo.Node2Policy,
    }
    
    c.HTML(http.StatusOK, "channel_detail", gin.H{
        "Channel": detail,
        "title":   "Detalhes do Canal",
    })
}