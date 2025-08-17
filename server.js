const express = require("express");
const cors = require("cors");
const { execFile } = require("child_process");
const path = require("path");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const crypto = require("crypto");
const fs = require("fs").promises;

const app = express();
app.use(cors({
  origin: 'http://localhost:7700'
}));
// CONFIGURAÇÃO DO BANCO DE DADOS SIMPLES (JSON)
const DB_FILE = path.join(__dirname, 'apikeys.json');

// Função para carregar API keys do arquivo
async function loadApiKeys() {
    try {
        const data = await fs.readFile(DB_FILE, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        // Se o arquivo não existir, criar um vazio
        const emptyDb = { apiKeys: {} };
        await saveApiKeys(emptyDb);
        return emptyDb;
    }
}

// Função para salvar API keys no arquivo
async function saveApiKeys(data) {
    await fs.writeFile(DB_FILE, JSON.stringify(data, null, 2));
}

// Função para gerar API Key segura
function generateApiKey() {
    return 'ak_' + crypto.randomBytes(32).toString('hex');
}

// Função para verificar se API Key é válida e não expirada
async function validateApiKey(apiKey) {
    const db = await loadApiKeys();
    const keyData = db.apiKeys[apiKey];
    
    if (!keyData) {
        return { valid: false, reason: 'API Key não encontrada' };
    }
    
    const now = new Date();
    const expiryDate = new Date(keyData.expiresAt);
    
    if (now > expiryDate) {
        // Remove chave expirada automaticamente
        delete db.apiKeys[apiKey];
        await saveApiKeys(db);
        return { valid: false, reason: 'API Key expirada' };
    }
    
    // Atualiza último uso
    keyData.lastUsed = now.toISOString();
    keyData.usageCount = (keyData.usageCount || 0) + 1;
    await saveApiKeys(db);
    
    return { 
        valid: true, 
        keyData: {
            name: keyData.name,
            createdAt: keyData.createdAt,
            expiresAt: keyData.expiresAt,
            usageCount: keyData.usageCount
        }
    };
}

// Função para limpar chaves expiradas automaticamente
async function cleanExpiredKeys() {
    const db = await loadApiKeys();
    const now = new Date();
    let removedCount = 0;
    
    for (const [key, data] of Object.entries(db.apiKeys)) {
        if (new Date(data.expiresAt) < now) {
            delete db.apiKeys[key];
            removedCount++;
        }
    }
    
    if (removedCount > 0) {
        await saveApiKeys(db);
        console.log(`🧹 Removidas ${removedCount} API keys expiradas`);
    }
}

// Executar limpeza a cada 6 horas
setInterval(cleanExpiredKeys, 6 * 60 * 60 * 1000);

// MIDDLEWARES DE SEGURANÇA
app.use(helmet());
app.use(cors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || 'http://localhost:3000',
    credentials: true
}));

// RATE LIMITING
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 100,
    message: { error: "Muitas tentativas. Tente novamente em 15 minutos." }
});
app.use(limiter);

// PARSING DE DADOS
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// LOGGING MIDDLEWARE
app.use((req, res, next) => {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] ${req.method} ${req.path} - IP: ${req.ip}`);
    next();
});

// MIDDLEWARE DE AUTENTICAÇÃO
async function authenticateApiKey(req, res, next) {
    const apiKey = req.headers['x-api-key'] || req.query.apikey;
    
    if (!apiKey) {
        return res.status(401).json({ 
            error: "API Key obrigatória",
            message: "Inclua sua API Key no header 'X-API-Key' ou no query parameter 'apikey'"
        });
    }
    
    try {
        const validation = await validateApiKey(apiKey);
        
        if (!validation.valid) {
            return res.status(401).json({ 
                error: "API Key inválida",
                message: validation.reason
            });
        }
        
        // Adiciona informações da API Key na requisição
        req.apiKeyData = validation.keyData;
        next();
        
    } catch (error) {
        console.error('Erro na validação da API Key:', error);
        return res.status(500).json({ error: "Erro interno de autenticação" });
    }
}

// VALIDAÇÃO E SANITIZAÇÃO (mantidas do código anterior)
const isValidUrl = (url) => {
    try {
        const parsedUrl = new URL(url);
        return ['http:', 'https:'].includes(parsedUrl.protocol);
    } catch {
        return false;
    }
};

const sanitizeInput = (input) => {
    return input.replace(/[;&|`$(){}[\]]/g, '');
};

const ALLOWED_TYPES = ['mp3', 'mp4', 'wav', 'webm'];
const ALLOWED_PLATFORMS = ['youtube', 'spotify', 'soundcloud'];

// FUNÇÃO UTILITÁRIA PARA EXECUÇÃO SEGURA
const executeScript = (scriptName, args, timeout = 30000) => {
    return new Promise((resolve, reject) => {
        const sanitizedArgs = args.map(arg => sanitizeInput(String(arg)));
        
        execFile("python3", [scriptName, ...sanitizedArgs], {
            timeout,
            maxBuffer: 1024 * 1024 * 10,
            cwd: __dirname
        }, (err, stdout, stderr) => {
            if (err) {
                console.error(`Erro ao executar ${scriptName}:`, err.message);
                if (stderr) console.error('STDERR:', stderr);
                reject(new Error(`Erro interno do servidor`));
                return;
            }

            try {
                const result = JSON.parse(stdout);
                resolve(result);
            } catch (parseErr) {
                console.error('Erro ao parsear JSON:', parseErr.message);
                reject(new Error('Erro ao processar resposta do servidor'));
            }
        });
    });
};

// ==================== ROTAS DE GERENCIAMENTO DE API KEYS ====================

// 🔑 GERAR NOVA API KEY
app.post("/api/keys/generate", async (req, res) => {
    try {
        const { name, adminSecret } = req.body;
        
        // Verificar senha de admin (você deve definir isso no .env)
        if (adminSecret !== process.env.ADMIN_SECRET) {
            return res.status(403).json({ 
                error: "Acesso negado",
                message: "Admin secret inválido"
            });
        }
        
        if (!name || name.trim().length < 3) {
            return res.status(400).json({ 
                error: "Nome obrigatório (mínimo 3 caracteres)" 
            });
        }
        
        const apiKey = generateApiKey();
        const now = new Date();
        const expiresAt = new Date(now.getTime() + (30 * 24 * 60 * 60 * 1000)); // 30 dias
        
        const db = await loadApiKeys();
        
        db.apiKeys[apiKey] = {
            name: name.trim(),
            createdAt: now.toISOString(),
            expiresAt: expiresAt.toISOString(),
            lastUsed: null,
            usageCount: 0
        };
        
        await saveApiKeys(db);
        
        console.log(`✅ Nova API Key gerada: ${name}`);
        
        res.json({
            success: true,
            message: "API Key gerada com sucesso",
            data: {
                apiKey: apiKey,
                name: name.trim(),
                expiresAt: expiresAt.toISOString(),
                validFor: "30 dias"
            }
        });
        
    } catch (error) {
        console.error('Erro ao gerar API Key:', error);
        res.status(500).json({ error: "Erro interno do servidor" });
    }
});

// 🗑️ DELETAR API KEY
app.delete("/api/keys/:apiKey", async (req, res) => {
    try {
        const { apiKey } = req.params;
        const { adminSecret } = req.body;
        
        // Verificar senha de admin
        if (adminSecret !== process.env.ADMIN_SECRET) {
            return res.status(403).json({ 
                error: "Acesso negado",
                message: "Admin secret inválido"
            });
        }
        
        const db = await loadApiKeys();
        
        if (!db.apiKeys[apiKey]) {
            return res.status(404).json({ 
                error: "API Key não encontrada" 
            });
        }
        
        const keyName = db.apiKeys[apiKey].name;
        delete db.apiKeys[apiKey];
        await saveApiKeys(db);
        
        console.log(`🗑️ API Key deletada: ${keyName}`);
        
        res.json({
            success: true,
            message: `API Key '${keyName}' deletada com sucesso`
        });
        
    } catch (error) {
        console.error('Erro ao deletar API Key:', error);
        res.status(500).json({ error: "Erro interno do servidor" });
    }
});

// 📋 LISTAR API KEYS (apenas admin)
app.get("/api/keys/list", async (req, res) => {
    try {
        const { adminSecret } = req.query;
        
        if (adminSecret !== process.env.ADMIN_SECRET) {
            return res.status(403).json({ 
                error: "Acesso negado",
                message: "Admin secret inválido"
            });
        }
        
        const db = await loadApiKeys();
        const now = new Date();
        
        const keysList = Object.entries(db.apiKeys).map(([key, data]) => ({
            apiKey: key,
            name: data.name,
            createdAt: data.createdAt,
            expiresAt: data.expiresAt,
            lastUsed: data.lastUsed,
            usageCount: data.usageCount || 0,
            isExpired: new Date(data.expiresAt) < now,
            daysUntilExpiry: Math.ceil((new Date(data.expiresAt) - now) / (24 * 60 * 60 * 1000))
        }));
        
        res.json({
            success: true,
            total: keysList.length,
            data: keysList
        });
        
    } catch (error) {
        console.error('Erro ao listar API Keys:', error);
        res.status(500).json({ error: "Erro interno do servidor" });
    }
});

// 🔍 VERIFICAR STATUS DA API KEY
app.get("/api/keys/status", authenticateApiKey, async (req, res) => {
    try {
        const apiKey = req.headers['x-api-key'] || req.query.apikey;
        const db = await loadApiKeys();
        const keyData = db.apiKeys[apiKey];
        const now = new Date();
        const expiryDate = new Date(keyData.expiresAt);
        
        res.json({
            success: true,
            data: {
                name: keyData.name,
                createdAt: keyData.createdAt,
                expiresAt: keyData.expiresAt,
                lastUsed: keyData.lastUsed,
                usageCount: keyData.usageCount || 0,
                daysUntilExpiry: Math.ceil((expiryDate - now) / (24 * 60 * 60 * 1000)),
                isValid: true
            }
        });
        
    } catch (error) {
        console.error('Erro ao verificar status:', error);
        res.status(500).json({ error: "Erro interno do servidor" });
    }
});

// ==================== ROTAS PROTEGIDAS (REQUEREM API KEY) ====================

// 🎵 ROTA DOWNLOAD PROTEGIDA
app.get("/api/download/:platform", authenticateApiKey, async (req, res) => {
    try {
        const { platform } = req.params;
        const { url, type } = req.query;

        // Validações (mantidas do código anterior)
        if (!platform || !ALLOWED_PLATFORMS.includes(platform.toLowerCase())) {
            return res.status(400).json({ 
                error: "Plataforma inválida",
                allowedPlatforms: ALLOWED_PLATFORMS
            });
        }

        if (!url || !type) {
            return res.status(400).json({ 
                error: "Parâmetros 'url' e 'type' são obrigatórios" 
            });
        }

        if (!isValidUrl(url)) {
            return res.status(400).json({ 
                error: "URL inválida ou protocolo não permitido" 
            });
        }

        if (!ALLOWED_TYPES.includes(type.toLowerCase())) {
            return res.status(400).json({ 
                error: "Tipo de arquivo inválido",
                allowedTypes: ALLOWED_TYPES
            });
        }

        // Executar script
        const result = await executeScript("downloader.py", [url, type], 45000);
        
        res.json({
            success: true,
            data: result,
            apiKeyInfo: {
                name: req.apiKeyData.name,
                usageCount: req.apiKeyData.usageCount
            }
        });

    } catch (error) {
        console.error('Erro na rota download:', error);
        res.status(500).json({ 
            error: "Erro interno do servidor",
            message: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// 🔍 ROTA SEARCH PROTEGIDA
app.get("/api/search/youtube", authenticateApiKey, async (req, res) => {
    try {
        const { query, limit = 10 } = req.query;

        if (!query || query.trim().length < 2) {
            return res.status(400).json({ 
                error: "Parâmetro 'query' deve ter pelo menos 2 caracteres" 
            });
        }

        if (query.length > 100) {
            return res.status(400).json({ 
                error: "Query muito longa (máximo 100 caracteres)" 
            });
        }

        const numLimit = parseInt(limit);
        if (isNaN(numLimit) || numLimit < 1 || numLimit > 50) {
            return res.status(400).json({ 
                error: "Limit deve ser um número entre 1 e 50" 
            });
        }

        const result = await executeScript("youtube_search.py", [query, numLimit]);
        
        res.json({
            success: true,
            data: result,
            apiKeyInfo: {
                name: req.apiKeyData.name,
                usageCount: req.apiKeyData.usageCount
            }
        });

    } catch (error) {
        console.error('Erro na rota search:', error);
        res.status(500).json({ 
            error: "Erro interno do servidor",
            message: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// ==================== ROTAS PÚBLICAS ====================

// 📁 SERVIR ARQUIVOS ESTÁTICOS
app.use('/downloads', express.static(path.join(__dirname, 'downloads'), {
    maxAge: '1h',
    etag: true,
    lastModified: true,
    setHeaders: (res, path) => {
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
    }
}));

// ❤️ HEALTH CHECK
app.get("/api/health", (req, res) => {
    res.json({ 
        status: "OK", 
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        version: "2.0.0"
    });
});

// 📚 DOCUMENTAÇÃO DA API
app.get("/api/docs", (req, res) => {
    res.json({
        message: "API de Download e Busca",
        version: "2.0.0",
        authentication: "API Key obrigatória",
        endpoints: {
            "/api/keys/generate": "POST - Gerar nova API Key (admin)",
            "/api/keys/:apiKey": "DELETE - Deletar API Key (admin)",
            "/api/keys/list": "GET - Listar todas as API Keys (admin)",
            "/api/keys/status": "GET - Verificar status da sua API Key",
            "/api/download/:platform": "GET - Download de conteúdo (protegido)",
            "/api/search/youtube": "GET - Buscar no YouTube (protegido)"
        },
        usage: {
            headers: "X-API-Key: sua_api_key_aqui",
            alternative: "?apikey=sua_api_key_aqui"
        }
    });
});

// MIDDLEWARE DE ERRO GLOBAL
app.use((err, req, res, next) => {
    console.error('Erro não tratado:', err);
    res.status(500).json({ 
        error: "Erro interno do servidor" 
    });
});

// ROTA 404
app.use((req, res) => {
    res.status(404).json({ 
        error: "Rota não encontrada",
        suggestion: "Verifique a documentação em /api/docs"
    });
});

// CONFIGURAÇÕES DO SERVIDOR
const PORT = process.env.PORT || 3000;
const HOST = '0.0.0.0';

const server = app.listen(PORT, HOST, () => {
    console.log(`🚀 Servidor rodando em http://${HOST}:${PORT}`);
    console.log(`🔐 Sistema de autenticação ativado`);
    console.log(`📝 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`📚 Documentação: http://${HOST}:${PORT}/api/docs`);

    // Executar limpeza inicial
    cleanExpiredKeys();
});

// GRACEFUL SHUTDOWN
process.on('SIGTERM', () => {
    console.log('🛑 SIGTERM recebido, fechando servidor...');
    server.close(() => {
        console.log('✅ Servidor fechado graciosamente');
        process.exit(0);
    });
});

module.exports = app;
