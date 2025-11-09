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
    "strings"
    "net/url"

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
    ChanId       uint64  
    Active       bool
}

type ChannelDetail struct {
    Alias    string
    ChanId   uint64
    Capacity int64
    ChanPoint    string
    Node1Policy *lnrpc.RoutingPolicy
    Node2Policy *lnrpc.RoutingPolicy
}

// ⚙️ Função para resolver LN Address
type LNURLPayResponse struct {
    Callback        string `json:"callback"`
    MinSendable     int64  `json:"minSendable"`
    MaxSendable     int64  `json:"maxSendable"`
    Metadata        string `json:"metadata"`
    Tag             string `json:"tag"`
    AllowsNostr     bool   `json:"allowsNostr"`
    CommentAllowed  int    `json:"commentAllowed"`
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
    router.POST("/channels/open", openChannelHandler)
    router.GET("/channels/:chanId", showChannelHandler)
    router.GET("/policy/update", updatePolicyHandler)
    router.POST("/policy/update", updatePolicyHandler)
    router.GET("/policy/form", updatePolicyFormHandler)
    router.POST("/decode_invoice", decodeInvoiceHandler)
    router.POST("/delete_node", deleteNodeHandler)

    
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

func deleteNodeHandler(c *gin.Context) {
    nodeAddress := c.PostForm("node_address")
    if nodeAddress == "" {
        c.String(http.StatusBadRequest, "Endereço do node não fornecido")
        return
    }

    err := db.Update(func(tx *bolt.Tx) error {
        b := tx.Bucket([]byte("Nodes"))
        return b.Delete([]byte(nodeAddress))
    })

    if err != nil {
        c.String(http.StatusInternalServerError, "Erro ao excluir node: %v", err)
        return
    }

    c.Redirect(http.StatusFound, "/")
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
        "add": func(a, b uint32, c ...uint32) uint32 {
            sum := a + b
            for _, v := range c {
                sum += v
            }
            return sum
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
        "update_policy": "templates/update_policy.html",
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
    ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
    defer cancel()

    _, err = client.GetInfo(ctx, &lnrpc.GetInfoRequest{})
    if err != nil {
        return nil, fmt.Errorf("erro ao autenticar no LND: %v", err)
    }

    return client, nil
}

func resolveLNAddress(address string, amountSats int64, comment string) (string, error) {
    parts := strings.Split(address, "@")
    if len(parts) != 2 {
        return "", fmt.Errorf("formato de Lightning Address inválido")
    }

    user := parts[0]
    domain := parts[1]
    metadataURL := fmt.Sprintf("https://%s/.well-known/lnurlp/%s", domain, user)

    // 1. Buscar os dados da LNURL
    resp, err := http.Get(metadataURL)
    if err != nil {
        return "", fmt.Errorf("erro ao buscar LNURL: %v", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return "", fmt.Errorf("LNURLP retornou status %d", resp.StatusCode)
    }

    var payResp LNURLPayResponse
    err = json.NewDecoder(resp.Body).Decode(&payResp)
    if err != nil {
        return "", fmt.Errorf("erro ao decodificar resposta LNURLP: %v", err)
    }

    if payResp.Callback == "" {
        return "", fmt.Errorf("callback ausente na resposta LNURLP")
    }

    // 2. Montar callback com parâmetros
    callbackURL, err := url.Parse(payResp.Callback)
    if err != nil {
        return "", fmt.Errorf("callback inválido: %v", err)
    }

    q := callbackURL.Query()
    q.Set("amount", strconv.FormatInt(amountSats*1000, 10)) // em msats
    if comment != "" {
        q.Set("comment", comment)
    }
    callbackURL.RawQuery = q.Encode()

    // 3. Consultar o callback final
    finalResp, err := http.Get(callbackURL.String())
    if err != nil {
        return "", fmt.Errorf("erro ao consultar callback LNURL: %v", err)
    }
    defer finalResp.Body.Close()

    var data map[string]interface{}
    if err := json.NewDecoder(finalResp.Body).Decode(&data); err != nil {
        return "", fmt.Errorf("erro ao decodificar resposta do callback: %v", err)
    }

    pr, ok := data["pr"].(string)
    if !ok || pr == "" {
        return "", fmt.Errorf("payment Request ausente na resposta final")
    }

    return pr, nil
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
    // Soma local_balance + unsettled_local_balance
    totalLocal := channelBalance.LocalBalance.Sat + channelBalance.UnsettledRemoteBalance.Sat
    // Mostra um emoji verde se true, vermelho se false
    syncedToChain := "❌"
    if info.SyncedToChain {
        syncedToChain = "✅"
    }
    syncedToGraph := "❌"
    if info.SyncedToGraph {
        syncedToGraph = "✅"
    }
    c.HTML(http.StatusOK, "dashboard", gin.H{
        "NodeInfo":       info,
        "Balance":        balance,
        "ChannelBalance": totalLocal,
        "SyncedToChain":  syncedToChain,
        "SyncedToGraph":  syncedToGraph,
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
// Decodificar invoice
func decodeInvoiceHandler(c *gin.Context) {
    session := sessions.Default(c)
    addrI := session.Get("node_address")
    if addrI == nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Node não conectado"})
        return
    }

    addr := addrI.(string)
    node, err := getNodeByAddress(addr)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao recuperar node"})
        return
    }

    client, err := connectLND(node.Address, node.MacaroonHex, node.TLSCertHex)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao conectar ao LND"})
        return
    }

    invoice := c.PostForm("payment_request")
    if invoice == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invoice não fornecida"})
        return
    }

    ctx := context.Background()
    decoded, err := client.DecodePayReq(ctx, &lnrpc.PayReqString{PayReq: invoice})
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Erro ao decodificar invoice"})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "amount_sat":  decoded.NumSatoshis,
        "description": decoded.Description,
    })
}

// 🚀 Handler de pagamento (atualizado)
func payInvoiceHandler(c *gin.Context) {
    session := sessions.Default(c)
    addrI := session.Get("node_address")
    if addrI == nil {
        c.Redirect(http.StatusFound, "/")
        return
    }
    addr := addrI.(string)

    node, err := getNodeByAddress(addr)
    if err != nil {
        c.String(http.StatusInternalServerError, "Erro ao recuperar node")
        return
    }

    client, err := connectLND(node.Address, node.MacaroonHex, node.TLSCertHex)
    if err != nil {
        c.String(http.StatusInternalServerError, "Erro ao conectar ao LND")
        return
    }

    rawInput := strings.ToLower(strings.TrimSpace(c.PostForm("payment_request")))
    rawInput = strings.TrimPrefix(rawInput, "lightning:")

    var paymentRequest string

    if strings.Contains(rawInput, "@") {
        // Lightning Address
        amountStr := c.PostForm("amount")
        amount, err := strconv.ParseInt(amountStr, 10, 64)
        if err != nil || amount <= 0 {
            c.HTML(http.StatusBadRequest, "pay", gin.H{"ErrorMessage": "Informe um valor válido para envio ao Lightning Address."})
            return
        }
        description := c.PostForm("description")

        pr, err := resolveLNAddress(rawInput, amount, description)
        if err != nil {
            c.HTML(http.StatusBadRequest, "pay", gin.H{"ErrorMessage": fmt.Sprintf("Erro ao resolver LN Address: %v", err)})
            return
        }
        paymentRequest = pr

    } else {
        // Invoice direta
        paymentRequest = rawInput
    }

    // Envia o pagamento
    sendReq := &lnrpc.SendRequest{PaymentRequest: paymentRequest}
    resp, err := client.SendPaymentSync(context.Background(), sendReq)
    if err != nil {
        c.HTML(http.StatusInternalServerError, "pay", gin.H{"ErrorMessage": fmt.Sprintf("Erro ao enviar pagamento: %v", err)})
        return
    }

    if resp.PaymentError != "" {
        c.HTML(http.StatusOK, "pay", gin.H{"ErrorMessage": fmt.Sprintf("Erro de pagamento: %v", resp.PaymentError)})
        return
    }

    c.HTML(http.StatusOK, "pay", gin.H{
        "result": gin.H{
            "message": "Pagamento enviado com sucesso!",
            "hash":    fmt.Sprintf("%x", resp.PaymentHash), // ✅
            "total_amt": resp.PaymentRoute.TotalAmt,
        },
    })
    
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
            Active:       channel.Active,
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
    chanIdStr := c.Param("chanId")
    chanId, err := strconv.ParseUint(chanIdStr, 10, 64)
    if err != nil {
        c.String(http.StatusBadRequest, "ID de canal inválido: %v", err)
        return
    }

    // Recupera o alias passado via query da listagem.
    alias := c.Query("alias")
    if alias == "" {
        alias = "(Alias não disponível)"
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
    
    // Obtém informações do canal.
    chanInfo, err := client.GetChanInfo(context.Background(), &lnrpc.ChanInfoRequest{
        ChanId: chanId,
    })
    if err != nil {
        c.String(http.StatusInternalServerError, "Erro ao recuperar dados do canal: %v", err)
        return
    }
    
    // Use GetInfo para obter a identidade do nó local.
    localInfo, err := client.GetInfo(context.Background(), &lnrpc.GetInfoRequest{})
    if err != nil {
        c.String(http.StatusInternalServerError, "Erro ao recuperar dados do nó local: %v", err)
        return
    }
    localPubKey := localInfo.IdentityPubkey

    detail := ChannelDetail{
        Alias:     alias,
        ChanId:    chanInfo.ChannelId,
        Capacity:  chanInfo.Capacity,
        ChanPoint: chanInfo.ChanPoint,
    }
    
    // Determina qual política é do nó local comparando as pubkeys.
    // Supondo que chanInfo.Node1Pub e chanInfo.Node2Pub estão disponíveis.
    if localPubKey == chanInfo.Node1Pub {
        detail.Node1Policy = chanInfo.Node1Policy  // politica do nó local
        detail.Node2Policy = chanInfo.Node2Policy  // politica do nó remoto
    } else if localPubKey == chanInfo.Node2Pub {
        detail.Node1Policy = chanInfo.Node2Policy  // politica do nó local
        detail.Node2Policy = chanInfo.Node1Policy  // politica do nó remoto
    } else {
        // Caso não coincida, use os valores originais e informe
        detail.Node1Policy = chanInfo.Node1Policy
        detail.Node2Policy = chanInfo.Node2Policy
        log.Println("A pubkey local não coincide com Node1Pub ou Node2Pub do canal.")
    }
    
    c.HTML(http.StatusOK, "channel_detail", gin.H{
        "Channel": detail,
        "title":   "Detalhes do Canal",
    })
}

func updatePolicyFormHandler(c *gin.Context) {
    // Recupera o channel point via query string.
    chanPoint := c.Query("chan_point")
    if chanPoint == "" {
        c.String(http.StatusBadRequest, "Channel point não informado")
        return
    }
    // Tenta recuperar o alias passado na query (da listagem)
    aliasQuery := c.Query("alias")
    
    var detail ChannelDetail // declara a variável antes de usá-la
    if aliasQuery != "" {
        detail.Alias = aliasQuery
    } else {
        detail.Alias = "(Alias não disponível)"
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
    
    // Obtenha a lista de canais e busque aquele cujo channel point bate
    channelsResp, err := client.ListChannels(context.Background(), &lnrpc.ListChannelsRequest{})
    if err != nil {
        c.String(http.StatusInternalServerError, "Erro ao listar canais: %v", err)
        return
    }
    
    found := false
    for _, ch := range channelsResp.Channels {
        if ch.ChannelPoint == chanPoint {
            // Preenche dados básicos do canal
            detail.ChanPoint = ch.ChannelPoint
            detail.ChanId = ch.ChanId
            detail.Capacity = ch.Capacity
            
            // Obtenha as políticas atuais do canal
            chanInfo, err := client.GetChanInfo(context.Background(), &lnrpc.ChanInfoRequest{
                ChanId: ch.ChanId,
            })
            if err == nil {
                // Agora recupere a pubkey do nó local
                localInfo, err := client.GetInfo(context.Background(), &lnrpc.GetInfoRequest{})
                if err != nil {
                    c.String(http.StatusInternalServerError, "Erro ao recuperar dados do nó local: %v", err)
                    return
                }
                localPubKey := localInfo.IdentityPubkey
                // Determine qual política pertence ao nó local
                if localPubKey == chanInfo.Node1Pub {
                    detail.Node1Policy = chanInfo.Node1Policy
                } else if localPubKey == chanInfo.Node2Pub {
                    detail.Node1Policy = chanInfo.Node2Policy
                } else {
                    detail.Node1Policy = chanInfo.Node1Policy
                    log.Println("A pubkey local não coincide com Node1Pub ou Node2Pub do canal.")
                }
            }
            found = true
            break
        }
    }
    
    if detail.Node1Policy == nil {
        detail.Node1Policy = &lnrpc.RoutingPolicy{
            FeeBaseMsat:            0,
            FeeRateMilliMsat:       0,
            InboundFeeBaseMsat:     0,
            InboundFeeRateMilliMsat: 0,
            TimeLockDelta:          0,
        }
    }
    if !found {
        c.String(http.StatusNotFound, "Canal não encontrado")
        return
    }
    
    c.HTML(http.StatusOK, "update_policy", gin.H{
        "Channel": detail,
        "title":   "Atualizar Políticas",
    })
}
func updatePolicyHandler(c *gin.Context) {
    // Recupera o node a partir da sessão.
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

    // Obtém os valores do formulário
    chanPoint := c.PostForm("chan_point")
    chanID := c.PostForm("chan_id")
    alias := c.PostForm("alias")
    feeBaseStr := c.PostForm("fee_base_msat")
    feeRateStr := c.PostForm("fee_rate_milli_msat")
    inboundFeeBaseStr := c.PostForm("inbound_fee_base_msat")
    inboundFeeRateStr := c.PostForm("inbound_fee_rate_milli_msat")
    timeLockDeltaStr := c.PostForm("time_lock_delta")

    // Conversões necessárias
    feeBase, err := strconv.ParseInt(feeBaseStr, 10, 64)
    if err != nil {
        c.String(http.StatusBadRequest, "Fee Base inválido")
        return
    }
    feeRate, err := strconv.ParseFloat(feeRateStr, 64)
    if err != nil {
        c.String(http.StatusBadRequest, "Fee Rate inválido")
        return
    }
    inboundFeeBase, err := strconv.ParseInt(inboundFeeBaseStr, 10, 64)
    if err != nil {
        c.String(http.StatusBadRequest, "Inbound Fee Base inválido")
        return
    }
    inboundFeeRate, err := strconv.ParseInt(inboundFeeRateStr, 10, 64)
    if err != nil {
        c.String(http.StatusBadRequest, "Inbound Fee Rate inválido")
        return
    }
    timeLockDelta, err := strconv.ParseUint(timeLockDeltaStr, 10, 32)
    if err != nil {
        c.String(http.StatusBadRequest, "Time Lock Delta inválido")
        return
    }

    log.Printf("Valores recebidos do formulário: chanPoint=%s, chanID=%s, feeBase=%d, feeRate=%f, inboundFeeBase=%d, inboundFeeRate=%d, timeLockDelta=%d",
        chanPoint, chanID, feeBase, feeRate, inboundFeeBase, inboundFeeRate, timeLockDelta)

    parts := strings.Split(chanPoint, ":")
    if len(parts) != 2 {
        c.String(http.StatusBadRequest, "Formato do channel point inválido")
        return
    }
    txidHex := parts[0]
    outputIdx, err := strconv.ParseUint(parts[1], 10, 32)
    if err != nil {
        c.String(http.StatusBadRequest, "Output index inválido no channel point")
        return
    }

    log.Printf("TXID: %s, Output Index: %d", txidHex, outputIdx)

    // Converte feeRate para ppm
    feeRatePpm := uint32(feeRate)

    policyReq := &lnrpc.PolicyUpdateRequest{
        BaseFeeMsat:   feeBase,
        FeeRatePpm:    feeRatePpm,
        TimeLockDelta: uint32(timeLockDelta),
        InboundFee: &lnrpc.InboundFee{
            BaseFeeMsat: int32(inboundFeeBase),
            FeeRatePpm:  int32(inboundFeeRate),
        },
        Scope: &lnrpc.PolicyUpdateRequest_ChanPoint{
            ChanPoint: &lnrpc.ChannelPoint{
                FundingTxid: &lnrpc.ChannelPoint_FundingTxidStr{
                    FundingTxidStr: txidHex,
                },
                OutputIndex: uint32(outputIdx),
            },
        },
    }

    log.Printf("Enviando PolicyUpdateRequest: %+v", policyReq)

    // Conecta ao LND
    client, err := connectLND(node.Address, node.MacaroonHex, node.TLSCertHex)
    if err != nil {
        c.String(http.StatusInternalServerError, "Erro ao conectar ao LND: %v", err)
        return
    }
    
    // Chama o método UpdateChannelPolicy
    _, err = client.UpdateChannelPolicy(context.Background(), policyReq)
    if err != nil {
        log.Printf("Erro ao atualizar política: %v", err)
        c.HTML(http.StatusOK, "update_policy", gin.H{
            "title":   "Atualizar Políticas",
            "Error":   fmt.Sprintf("Erro ao atualizar política: %v", err),
            "Channel": gin.H{
                "ChanPoint": chanPoint,
                "ChanId": chanID,
                "Alias": alias,
                "Node1Policy": gin.H{
                    "FeeBaseMsat": feeBase,
                    "FeeRateMilliMsat": feeRate,
                    "InboundFeeBaseMsat": inboundFeeBase,
                    "InboundFeeRateMilliMsat": inboundFeeRate,
                    "TimeLockDelta": timeLockDelta,
                },
            },
        })
        return
    }

    
    log.Printf("Alias recebido do formulário: %q", alias)
    if alias == "" {
        alias = "(Alias não disponível)"
    }
    // Reutiliza a variável chanID já obtida do formulário (não re-declarada)
    redirectURL := fmt.Sprintf("/channels/%s?alias=%s", chanID, url.QueryEscape(alias))
    c.Redirect(http.StatusFound, redirectURL)
}

// Abrir canal via modal (conecta peer e abre canal)
func openChannelHandler(c *gin.Context) {
    session := sessions.Default(c)
    addrI := session.Get("node_address")
    if addrI == nil {
        c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Node não conectado"})
        return
    }
    addr := addrI.(string)

    node, err := getNodeByAddress(addr)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": fmt.Sprintf("Erro ao recuperar node: %v", err)})
        return
    }

    client, err := connectLND(node.Address, node.MacaroonHex, node.TLSCertHex)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": fmt.Sprintf("Erro ao conectar ao LND: %v", err)})
        return
    }

    peerInfo := strings.TrimSpace(c.PostForm("peer_info"))
    amountStr := strings.TrimSpace(c.PostForm("amount_sats"))
    satVbStr := strings.TrimSpace(c.PostForm("sat_per_vbyte"))
    closeAddr := strings.TrimSpace(c.PostForm("close_address"))

    if peerInfo == "" || amountStr == "" || satVbStr == "" {
        c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Preencha Peer, Valor (sats) e Taxa (sat/vByte)"})
        return
    }

    // Parse peer_info: pubkey@host:port
    parts := strings.Split(peerInfo, "@")
    if len(parts) != 2 {
        c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Formato de peer inválido. Use pubkey@host:port"})
        return
    }
    pubkey := strings.TrimSpace(parts[0])
    hostport := strings.TrimSpace(parts[1])
    if !strings.Contains(hostport, ":") {
        c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Endereço do peer deve conter host:port"})
        return
    }

    amount, err := strconv.ParseInt(amountStr, 10, 64)
    if err != nil || amount <= 0 {
        c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Valor de canal inválido. Informe satoshis > 0."})
        return
    }
    satVb, err := strconv.ParseUint(satVbStr, 10, 64)
    if err != nil || satVb == 0 {
        c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Taxa inválida. Use sat/vByte >= 1."})
        return
    }

    // 1) Conectar ao peer (ignora erro se já conectado)
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    _, err = client.ConnectPeer(ctx, &lnrpc.ConnectPeerRequest{
        Addr: &lnrpc.LightningAddress{
            Pubkey: pubkey,
            Host:   hostport,
        },
        Perm:    false,
        Timeout: 15,
    })
    if err != nil {
        le := strings.ToLower(err.Error())
        if !(strings.Contains(le, "already connected") || strings.Contains(le, "connected to peer")) {
            c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": fmt.Sprintf("Falha ao conectar ao peer: %v", err)})
            return
        }
    }

    // 2) Abrir canal (OpenChannelSync)
    openReq := &lnrpc.OpenChannelRequest{
        NodePubkeyString:   pubkey,
        LocalFundingAmount: amount,
        SatPerVbyte:        satVb,
    }
    if closeAddr != "" {
        openReq.CloseAddress = closeAddr
    }

    cp, err := client.OpenChannelSync(ctx, openReq)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": fmt.Sprintf("Erro ao abrir canal: %v", err)})
        return
    }

    // Obter TXID de forma confiável: usa string se disponível,
    // caso contrário converte os bytes (revertendo endianness) para hex.
    txidStr := cp.GetFundingTxidStr()
    if txidStr == "" {
        b := cp.GetFundingTxidBytes()
        if len(b) > 0 {
            for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
                b[i], b[j] = b[j], b[i]
            }
            txidStr = hex.EncodeToString(b)
        }
    }

    c.JSON(http.StatusOK, gin.H{
        "status":       "ok",
        "funding_txid": txidStr,
        "output_index": cp.GetOutputIndex(),
    })
}
