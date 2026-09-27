using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Text.Json;

// ==== НАСТРОЙКИ ====
// Читаются из appsettings.json рядом с исполняемым файлом (копируется при сборке).
// Значения по умолчанию — в классе ProxyConfig в конце файла.
var configPath = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
var configFound = File.Exists(configPath);

var consoleLock = new object();

ProxyConfig config;
if (configFound)
{
    config = JsonSerializer.Deserialize<ProxyConfig>(
        await File.ReadAllTextAsync(configPath),
        new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? new ProxyConfig();
}
else
{
    config = new ProxyConfig();
}

// Локальный оверрайд секрета: appsettings.json содержит только пример UpstreamProxyUrl
// (файл коммитится), а реальные креды лежат в appsettings.local.json, который в .gitignore.
var localConfigPath = Path.Combine(AppContext.BaseDirectory, "appsettings.local.json");
if (File.Exists(localConfigPath))
{
    using var localDoc = JsonDocument.Parse(await File.ReadAllTextAsync(localConfigPath));
    if (localDoc.RootElement.TryGetProperty("UpstreamProxyUrl", out var localUpstream) &&
        localUpstream.GetString() is { Length: > 0 } localUpstreamUrl)
    {
        config.UpstreamProxyUrl = localUpstreamUrl;
    }
}

if (string.IsNullOrWhiteSpace(config.UpstreamProxyUrl) ||
    !Uri.TryCreate(config.UpstreamProxyUrl, UriKind.Absolute, out var upstreamUri) ||
    string.IsNullOrEmpty(upstreamUri.Host))
{
    // Явно различаем «файла нет» и «в файле пусто»: иначе легко вернуться к настройкам
    // по умолчанию с пустым upstream и долго гадать, почему прокси не работает.
    LogError(configFound
        ? $"В {configPath} не задан корректный UpstreamProxyUrl (пример: http://user:pass@host:port)."
        : $"Не найден {configPath} — а в настройках по умолчанию UpstreamProxyUrl пустой. " +
          "Создайте appsettings.json рядом с .csproj с заполненным UpstreamProxyUrl.");
    return 1;
}
// ===================

var listenHost = IPAddress.TryParse(config.ListenHost, out var parsedListenHost)
    ? parsedListenHost
    : IPAddress.Loopback;

var upstreamHost = upstreamUri.Host;
var upstreamPort = upstreamUri.Port;
var useTls = upstreamUri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase);

string? proxyAuthHeader = null;
if (!string.IsNullOrEmpty(upstreamUri.UserInfo))
{
    var parts = upstreamUri.UserInfo.Split(':', 2);
    var user = parts[0];
    var pass = parts.Length > 1 ? parts[1] : "";
    var auth = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{user}:{pass}"));
    proxyAuthHeader = $"Proxy-Authorization: Basic {auth}\r\n";
}

// Заголовки, которые нельзя переносить наверх: прокси-специфичные (мы подставляем свои)
// и Connection (мы сами форсируем Connection: close).
// Остальные заголовки, включая Transfer-Encoding, сохраняются: тело пересылается
// побайтово, поэтому разметка chunked должна доехать до upstream вместе с телом.
var strippedHeaders = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
{
    "Proxy-Authorization",
    "Proxy-Connection",
    "Connection",
};

var listener = new TcpListener(listenHost, config.ListenPort);
listener.Start();
var upstreamScheme = useTls ? "https" : "http";
LogInfo($"Локальный HTTP-прокси: http://{listenHost}:{config.ListenPort}");
LogInfo($"Upstream: {upstreamScheme}://{upstreamHost}:{upstreamPort}" +
   (proxyAuthHeader != null ? " (Basic-аутентификация)" : " (без аутентификации)"));
LogInfo($"Лимит заголовков: {config.MaxHeaderBytes} байт, таймаут: {config.HeaderTimeoutSeconds} с");

while (true)
{
    var client = await listener.AcceptTcpClientAsync();
    _ = Task.Run(() => HandleClientAsync(client));
}

async Task HandleClientAsync(TcpClient client)
{
    using (client)
    {
        try
        {
            var clientStream = client.GetStream();
            var headerBytes = await ReadHeadersAsync(clientStream);
            if (headerBytes == null)
            {
                LogError("заголовки не получены или превышен лимит — соединение закрыто");
                return;
            }

            // Latin1 — побайтовое взаимно-однозначное кодирование, поэтому заголовки
            // с не-ASCII байтами едут наверх без искажений.
            var headerText = Encoding.Latin1.GetString(headerBytes);
            var lines = headerText.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
            if (lines.Length == 0) return;

            var parts = lines[0].Split(' ', 3);
            if (parts.Length < 3)
            {
                LogError($"нераспознанная строка запроса: {lines[0]}");
                return;
            }

            var method = parts[0];
            var target = parts[1];
            var version = parts[2];

            using var upstream = new TcpClient();
            await upstream.ConnectAsync(upstreamHost, upstreamPort);
            Stream upstreamStream = upstream.GetStream();

            if (useTls)
            {
                // Пустой список SslProtocols отдаёт выбор политике ОС: туннель настроен на
                // Tls/Tls12, а сервер выше может требовать Tls13 — тогда handshake отвалится.
                // Явный список страхует от этого.
                var ssl = new SslStream(upstreamStream, false,
                    (sender, cert, chain, errors) => config.AllowUntrustedUpstreamCertificate);
                await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = upstreamHost,
                    EnabledSslProtocols = config.ParseUpstreamSslProtocols(),
                });
                upstreamStream = ssl;
            }

            if (method.Equals("CONNECT", StringComparison.OrdinalIgnoreCase))
            {
                LogInfo($"CONNECT → {target}");

                var connectReq = $"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{proxyAuthHeader}\r\n";
                await upstreamStream.WriteAsync(Encoding.Latin1.GetBytes(connectReq));

                var upstreamResp = await ReadHeadersAsync(upstreamStream);
                if (upstreamResp != null && IsSuccess(upstreamResp))
                {
                    await clientStream.WriteAsync(Encoding.Latin1.GetBytes(
                        "HTTP/1.1 200 Connection Established\r\n\r\n"));

                    var t1 = clientStream.CopyToAsync(upstreamStream);
                    var t2 = upstreamStream.CopyToAsync(clientStream);
                    await Task.WhenAny(t1, t2);
                }
                else
                {
                    LogError($"upstream отказал в CONNECT {target}: {FirstLine(upstreamResp)}");
                    await clientStream.WriteAsync(Encoding.Latin1.GetBytes(
                        "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"));
                }
            }
            else
            {
                // Обычный HTTP-запрос — отправляем через upstream как абсолютный URI.
                // Заголовки, влияющие на соединение (Connection, Transfer-Encoding, ...),
                // не переносим: при пересылке hop-by-hop они теряют смысл.
                var sb = new StringBuilder();
                sb.Append(lines[0]).Append("\r\n");
                foreach (var line in lines.Skip(1))
                {
                    var name = line.Split(':', 2)[0].Trim();
                    if (strippedHeaders.Contains(name)) continue;
                    sb.Append(line).Append("\r\n");
                }
                if (proxyAuthHeader != null) sb.Append(proxyAuthHeader);
                sb.Append("Connection: close\r\n\r\n");

                LogInfo($"{method} → {target}");

                if (!await WriteAllAsync(upstreamStream, Encoding.Latin1.GetBytes(sb.ToString()))) return;

                var t1 = clientStream.CopyToAsync(upstreamStream);
                var t2 = upstreamStream.CopyToAsync(clientStream);
                await Task.WhenAny(t1, t2);
            }
        }
        catch (OperationCanceledException)
        {
            LogError("таймаут при чтении заголовков");
        }
        catch (Exception ex)
        {
            LogError($"ошибка: {ex.Message}");
        }
    }
}

// Запись буфера целиком с таймаутом. Если запись не уложилась в таймаут — false.
async Task<bool> WriteAllAsync(Stream dest, byte[] payload)
{
    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
    try
    {
        await dest.WriteAsync(payload, cts.Token);
    }
    catch (OperationCanceledException)
    {
        LogError("таймаут записи в upstream");
        return false;
    }
    return true;
}

// Чтение заголовков до \r\n\r\n (включительно). null — если превышен лимит или истёк таймаут.
async Task<byte[]?> ReadHeadersAsync(Stream stream)
{
    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(config.HeaderTimeoutSeconds));

    var buffer = new MemoryStream();
    var buf = new byte[1];
    int state = 0; // 0-обычный, 1-\r, 2-\r\n, 3-\r\n\r
    while (buffer.Length < config.MaxHeaderBytes)
    {
        int n = await stream.ReadAsync(buf, cts.Token);
        if (n == 0) break;
        buffer.WriteByte(buf[0]);

        char c = (char)buf[0];
        if (c == '\r')
        {
            if (state == 2) state = 3;
            else state = 1;
        }
        else if (c == '\n')
        {
            if (state == 1) state = 2;
            else if (state == 3) return buffer.ToArray();
            else state = 0;
        }
        else state = 0;
    }
    return null;
}

// 2xx считаем успешным ответом upstream на CONNECT.
bool IsSuccess(byte[] headerBytes)
{
    var parts = FirstLine(headerBytes).Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
    return parts.Length >= 2 && parts[1].StartsWith('2');
}

string FirstLine(byte[]? headerBytes) =>
    headerBytes == null
        ? "ответ не получен"
        : Encoding.Latin1.GetString(headerBytes).Split("\r\n")[0];

void LogInfo(string message) => WriteLog("info", ConsoleColor.Green, message);
void LogError(string message) => WriteLog("error", ConsoleColor.Red, message);

void WriteLog(string level, ConsoleColor levelColor, string message)
{
    lock (consoleLock)
    {
        var previousColor = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.Write($"[{DateTime.Now:HH:mm:ss}] ");
        Console.ForegroundColor = levelColor;
        Console.Write(level);
        Console.ForegroundColor = previousColor;
        Console.WriteLine($" {message}");
    }
}

sealed class ProxyConfig
{
    public string ListenHost { get; set; } = "127.0.0.1";
    public int ListenPort { get; set; } = 18080;
    public string UpstreamProxyUrl { get; set; } = "";
    public int MaxHeaderBytes { get; set; } = 65536;
    public int HeaderTimeoutSeconds { get; set; } = 30;
    public bool AllowUntrustedUpstreamCertificate { get; set; } = true;

    /// <summary>
    /// Версии TLS для соединения с https-upstream, например "Tls12, Tls13".
    /// Пустая строка — политика ОС по умолчанию.
    /// </summary>
    public string UpstreamSslProtocols { get; set; } = "Tls12, Tls13";

    public SslProtocols ParseUpstreamSslProtocols() =>
        string.IsNullOrWhiteSpace(UpstreamSslProtocols)
            ? SslProtocols.None
            : Enum.Parse<SslProtocols>(UpstreamSslProtocols.Replace(" ", ""), ignoreCase: true);
}
