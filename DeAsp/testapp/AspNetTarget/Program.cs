using System.Security.Cryptography;
using System.Text;
using System.Web;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(o =>
{
    o.IdleTimeout = TimeSpan.FromHours(1);
    o.Cookie.Name = "ASP.NET_SessionId";
});
var app = builder.Build();
app.UseSession();

// ── Config ─────────────────────────────────────────────────────────────────
const string MACHINE_KEY = "DeAspTestKey_NotSecure_ForTestingOnly_1234567890abcdef";
const bool   MAC_ENABLED = true;   // set false to simulate disabled MAC

// ── Helpers ────────────────────────────────────────────────────────────────

static string H(string s) => HttpUtility.HtmlEncode(s);

string MakeViewState(string payload)
{
    var pb  = Encoding.UTF8.GetBytes(payload);
    var los = new List<byte> { 0xFF, 0x01, 0x05 };
    int len = pb.Length;
    while (len >= 0x80) { los.Add((byte)((len & 0x7F) | 0x80)); len >>= 7; }
    los.Add((byte)len);
    los.AddRange(pb);
    var data = los.ToArray();
    if (MAC_ENABLED)
    {
        var mac = HMACSHA1.HashData(Encoding.UTF8.GetBytes(MACHINE_KEY), data);
        data = [.. data, .. mac];
    }
    return Convert.ToBase64String(data);
}

bool VerifyViewState(string b64)
{
    if (!MAC_ENABLED) return true;
    try
    {
        var data = Convert.FromBase64String(b64.Length % 4 == 0 ? b64 : b64 + new string('=', 4 - b64.Length % 4));
        if (data.Length < 22) return false;
        var payload  = data[..^20];
        var mac      = data[^20..];
        var expected = HMACSHA1.HashData(Encoding.UTF8.GetBytes(MACHINE_KEY), payload);
        return CryptographicOperations.FixedTimeEquals(mac, expected);
    }
    catch { return false; }
}

string MakeEV(string id) => Convert.ToBase64String(Encoding.UTF8.GetBytes($"EV:{id}:{DateTime.UtcNow:yyyyMMddHH}"));

string Page(string title, string body)
{
    return "<!DOCTYPE html><html><head><meta charset='utf-8'><title>" + title + " | DeAsp Target</title>" +
           "<style>" +
           "body{font-family:Segoe UI,Arial,sans-serif;background:#f0f2f5;margin:0}" +
           ".header{background:#003366;color:#fff;padding:12px 24px;font-size:18px;font-weight:bold}" +
           ".container{max-width:700px;margin:40px auto;background:#fff;border-radius:6px;box-shadow:0 2px 8px rgba(0,0,0,.15);padding:32px}" +
           "input[type=text],input[type=password],textarea{width:100%;padding:8px;border:1px solid #ccc;border-radius:4px;box-sizing:border-box;margin-top:4px}" +
           ".btn{background:#003366;color:#fff;border:none;padding:10px 24px;border-radius:4px;cursor:pointer;font-size:14px}" +
           ".btn:hover{background:#004499}" +
           ".msg-warn{background:#fff3cd;border:1px solid #ffc107;padding:12px;border-radius:4px;color:#856404;margin-bottom:16px}" +
           ".msg-err{background:#f8d7da;border:1px solid #f5c6cb;padding:12px;border-radius:4px;color:#721c24;margin-bottom:16px}" +
           ".msg-ok{background:#d4edda;border:1px solid #c3e6cb;padding:12px;border-radius:4px;color:#155724;margin-bottom:16px}" +
           ".msg-info{background:#d1ecf1;border:1px solid #bee5eb;padding:12px;border-radius:4px;color:#0c5460;margin-bottom:16px}" +
           ".field{margin-bottom:16px}" +
           "label{font-size:13px;color:#333}" +
           ".hint{font-size:11px;color:#888;margin-top:3px}" +
           "table{width:100%;border-collapse:collapse}" +
           "td{padding:8px;border-bottom:1px solid #eee}" +
           "</style></head>" +
           "<body><div class='header'>ASP.NET Target App &mdash; DeAsp Test Server</div>" +
           "<div class='container'>" + body + "</div></body></html>";
}

// ── In-memory users & sessions ─────────────────────────────────────────────

var users = new Dictionary<string, (string hash, string mfa)>(StringComparer.OrdinalIgnoreCase)
{
    ["admin"]  = (Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("Password1!"))), "123456"),
    ["user"]   = (Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("letmein"))),    "654321"),
    ["victim"] = (Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("victim123"))),  "111111"),
};

// ── Routes ─────────────────────────────────────────────────────────────────

app.MapGet("/", () => Results.Redirect("/account/Login.aspx"));

// Login GET
app.MapGet("/account/Login.aspx", (HttpContext ctx) =>
{
    var vs = MakeViewState("Login|v1");
    var ev = MakeEV("Login");
    var html =
        "<h2>Sign In</h2>" +
        "<form method='POST' action='/account/Login.aspx'>" +
        $"<input type='hidden' name='__VIEWSTATE' value='{vs}' />" +
        "<input type='hidden' name='__VIEWSTATEGENERATOR' value='A1B2C3D4' />" +
        $"<input type='hidden' name='__EVENTVALIDATION' value='{ev}' />" +
        "<input type='hidden' name='__EVENTTARGET' value='' />" +
        "<input type='hidden' name='__EVENTARGUMENT' value='' />" +
        "<input type='hidden' name='__LASTFOCUS' value='' />" +
        "<div class='field'><label>Username<br><input type='text' name='ctl00$cphMaster$txtUsername' autocomplete='off' /></label></div>" +
        "<div class='field'><label>Password<br><input type='password' name='ctl00$cphMaster$txtPassword' /></label></div>" +
        "<button class='btn' type='submit'>Sign In</button>" +
        "</form>" +
        "<p class='hint'>Test accounts: admin/Password1!, user/letmein, victim/victim123</p>" +
        "<p class='hint'>MFA codes: admin→123456, user→654321, victim→111111</p>";
    return Results.Content(Page("Login", html), "text/html");
});

// Login POST
app.MapPost("/account/Login.aspx", async (HttpContext ctx) =>
{
    var form  = await ctx.Request.ReadFormAsync();
    var vs    = form["__VIEWSTATE"].ToString();
    var uname = form["ctl00$cphMaster$txtUsername"].ToString().Trim();
    var pass  = form["ctl00$cphMaster$txtPassword"].ToString();

    if (!VerifyViewState(vs))
    {
        ctx.Response.StatusCode = 500;
        await ctx.Response.WriteAsync(Page("Error",
            "<div class='msg-err'>Invalid ViewState — MAC validation failed. The page state has been tampered.</div>" +
            "<a href='/account/Login.aspx'>Back to Login</a>"));
        return;
    }

    if (users.TryGetValue(uname, out var u))
    {
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(pass)));
        if (hash == u.hash)
        {
            ctx.Session.SetString("username", uname.ToLower());
            ctx.Session.SetString("mfa_pending", "1");
            ctx.Response.Cookies.Append("CurrentUserFullName", uname);
            ctx.Response.Redirect("/account/MfaVerify.aspx");
            return;
        }
    }

    var vs2 = MakeViewState("Login|v1|err");
    var html2 =
        "<h2>Sign In</h2>" +
        "<div class='msg-err'>Invalid username or password.</div>" +
        "<form method='POST' action='/account/Login.aspx'>" +
        $"<input type='hidden' name='__VIEWSTATE' value='{vs2}' />" +
        $"<input type='hidden' name='__EVENTVALIDATION' value='{MakeEV("Login")}' />" +
        "<input type='hidden' name='__EVENTTARGET' value='' />" +
        $"<div class='field'><label>Username<br><input type='text' name='ctl00$cphMaster$txtUsername' value='{H(uname)}' /></label></div>" +
        "<div class='field'><label>Password<br><input type='password' name='ctl00$cphMaster$txtPassword' /></label></div>" +
        "<button class='btn' type='submit'>Sign In</button></form>";
    await ctx.Response.WriteAsync(Page("Login", html2));
});

// MFA GET
app.MapGet("/account/MfaVerify.aspx", (HttpContext ctx) =>
{
    var vs  = MakeViewState("MFA|v1");
    var ev  = MakeEV("MfaVerify");
    var tsm = string.Join("%3A", Enumerable.Range(0, 30).Select(_ => Guid.NewGuid().ToString("N")[..8]));
    var html =
        "<h2>Verify Sign In</h2>" +
        "<p>A verification code has been sent to your registered device.</p>" +
        "<form id='Form1' method='POST' action='/account/MfaVerify.aspx'>" +
        "<input type='hidden' name='ctl00$scriptManager' value='ctl00$cphMaster$udpPage|ctl00$cphMaster$btnVerify' />" +
        "<input type='hidden' name='__LASTFOCUS' value='' />" +
        $"<input type='hidden' name='ctl00_scriptManager_TSM' value='{tsm}' />" +
        "<input type='hidden' name='__EVENTTARGET' value='ctl00$cphMaster$btnVerify' />" +
        "<input type='hidden' name='__EVENTARGUMENT' value='' />" +
        $"<input type='hidden' name='__VIEWSTATE' value='{vs}' />" +
        "<input type='hidden' name='__VIEWSTATEGENERATOR' value='9D29872B' />" +
        "<input type='hidden' name='__SCROLLPOSITIONX' value='0' />" +
        "<input type='hidden' name='__SCROLLPOSITIONY' value='0' />" +
        $"<input type='hidden' name='__EVENTVALIDATION' value='{ev}' />" +
        "<div class='field'><label>Verification Code<br>" +
        "<input type='text' name='ctl00$cphMaster$txtCode' maxlength='6' autocomplete='off' style='width:160px;letter-spacing:6px;font-size:22px;' /></label>" +
        "<p class='hint'>Enter the 6-digit code</p></div>" +
        "<button class='btn' type='submit' name='ctl00$cphMaster$btnVerify' value='Verify'>Verify</button>" +
        "&nbsp;<button class='btn' type='submit' name='ctl00$cphMaster$btnResend' value='Resend' style='background:#666;'>Resend Code</button>" +
        "<input type='hidden' name='__ASYNCPOST' value='true' />" +
        "</form>" +
        "<p class='hint'>Session: login first. Codes: admin→123456, user→654321, victim→111111</p>";
    return Results.Content(Page("MFA Verify", html), "text/html");
});

// MFA POST (supports normal + AJAX UpdatePanel)
app.MapPost("/account/MfaVerify.aspx", async (HttpContext ctx) =>
{
    var form   = await ctx.Request.ReadFormAsync();
    var vs     = form["__VIEWSTATE"].ToString();
    var code   = form["ctl00$cphMaster$txtCode"].ToString().Trim();
    var isAjax = form["__ASYNCPOST"].ToString() == "true" ||
                 ctx.Request.Headers["X-MicrosoftAjax"].ToString().Contains("Delta");
    var uname  = ctx.Session.GetString("username") ?? "";

    // ViewState check
    if (!VerifyViewState(vs))
    {
        if (isAjax)
        {
            const string errMsg = "MAC validation failed — ViewState tampered.";
            ctx.Response.ContentType = "text/plain; charset=utf-8";
            await ctx.Response.WriteAsync($"{errMsg.Length}|error|500|{errMsg}|");
        }
        else
        {
            ctx.Response.StatusCode = 500;
            await ctx.Response.WriteAsync(Page("Error",
                "<div class='msg-err'>ViewState MAC validation failed. The page state is invalid or has been tampered with.</div>"));
        }
        return;
    }

    var failKey = $"fail_{uname}";
    var lockKey = $"lock_{uname}";
    int fails   = int.Parse(ctx.Session.GetString(failKey) ?? "0");
    bool locked = ctx.Session.GetString(lockKey) == "1";

    bool   success = false;
    string msgClass, message;

    if (locked)
    {
        msgClass = "ihpa-msgbar-warning";
        message  = "Your account is locked due to too many verification attempts. Please contact Website Support to reset multi-factor authentication.";
    }
    else if (string.IsNullOrEmpty(uname))
    {
        msgClass = "ihpa-msgbar-danger";
        message  = "Session expired. Please sign in again.";
    }
    else if (users.TryGetValue(uname, out var u) && code == u.mfa)
    {
        success  = true;
        msgClass = "ihpa-msgbar-info";
        message  = $"Welcome, {uname}! MFA verified successfully.";
        ctx.Session.Remove("mfa_pending");
        ctx.Session.SetString("authenticated", "1");
        ctx.Session.SetString(failKey, "0");
    }
    else
    {
        fails++;
        ctx.Session.SetString(failKey, fails.ToString());
        if (fails >= 3)
        {
            locked = true;
            ctx.Session.SetString(lockKey, "1");
            msgClass = "ihpa-msgbar-warning";
            message  = "Your account is locked due to too many verification attempts. Please contact Website Support to reset multi-factor authentication.";
        }
        else
        {
            msgClass = "ihpa-msgbar-danger";
            // Intentional: code echoed unencoded in AJAX UpdatePanel HTML for XSS testing
            message  = "Invalid code '" + code + "'. " + (3 - fails) + " attempt(s) remaining.";
        }
    }

    var newVs = MakeViewState($"MFA|v2|{DateTime.UtcNow.Ticks}");

    if (isAjax)
    {
        var panelHtml =
            "<div id='ctl00_cphMaster_udpPage_pnlMain' class='ihpa-update-panel-1' style='margin-bottom:5px;'>" +
            "<table style='width:100%;'><tr><td style='padding:0 10px;vertical-align:middle;'>" +
            "<span id='ctl00_cphMaster_udpPage_lblTitle' class='title'></span></td></tr></table></div>" +
            "<span id='ctl00_cphMaster_udpPage_msbMain'>" +
            "<table class='" + msgClass + "' style='table-layout:fixed;margin-bottom:5px'><tr>" +
            "<td style='text-align:left;padding:10px;word-wrap:break-word'>" + message + "</td>" +
            "<td style='text-align:right;vertical-align:top;width:12px'>" +
            "<a title='Close' href='javascript:void(0);' onclick=\"document.getElementById('ctl00_cphMaster_udpPage_msbMain').style.display='none'\">[x]</a>" +
            "</td></tr></table></span>";

        var s1 = "$('#ctl00_cphMaster_btnVerify').removeAttr('disabled');";
        var s2 = "$('#ctl00_cphMaster_btnResend').removeAttr('disabled');";
        var title = "Verify Sign In | ASP.NET Target";

        var sb = new StringBuilder();
        sb.Append($"{panelHtml.Length}|updatePanel|ctl00_cphMaster_udpPage|{panelHtml}|");
        sb.Append("0|hiddenField|__EVENTTARGET||");
        sb.Append("0|hiddenField|__EVENTARGUMENT||");
        sb.Append($"{newVs.Length}|hiddenField|__VIEWSTATE|{newVs}|");
        sb.Append("8|hiddenField|__VIEWSTATEGENERATOR|9D29872B|");
        sb.Append("1|hiddenField|__SCROLLPOSITIONX|0|");
        sb.Append("1|hiddenField|__SCROLLPOSITIONY|0|");
        sb.Append("0|asyncPostBackControlIDs||");
        sb.Append("0|postBackControlIDs||");
        sb.Append("25|updatePanelIDs||tctl00$cphMaster$udpPage,|");
        sb.Append("0|childUpdatePanelIDs||");
        sb.Append("24|panelsToRefreshIDs||ctl00$cphMaster$udpPage,|");
        sb.Append("3|asyncPostBackTimeout||600|");
        sb.Append("18|formAction||./MfaVerify.aspx|");
        sb.Append($"{title.Length}|pageTitle||{title}|");
        sb.Append($"{s1.Length}|scriptStartupBlock|ScriptContentNoTags|{s1}|");
        sb.Append($"{s2.Length}|scriptStartupBlock|ScriptContentNoTags|{s2}|");
        if (success)
        {
            const string redir = "/dashboard";
            sb.Append($"{redir.Length}|pageRedirect||{redir}|");
        }

        ctx.Response.ContentType = "text/plain; charset=utf-8";
        ctx.Response.Headers["X-AspNet-Version"] = "4.0.30319";
        await ctx.Response.WriteAsync(sb.ToString());
    }
    else
    {
        var htmlClass = msgClass == "ihpa-msgbar-warning" ? "msg-warn" :
                        msgClass == "ihpa-msgbar-danger"  ? "msg-err"  : "msg-ok";
        var html =
            "<h2>Verify Sign In</h2>" +
            $"<div class='{htmlClass}'>{message}</div>" +
            "<form method='POST' action='/account/MfaVerify.aspx'>" +
            $"<input type='hidden' name='__VIEWSTATE' value='{newVs}' />" +
            "<input type='hidden' name='__VIEWSTATEGENERATOR' value='9D29872B' />" +
            $"<input type='hidden' name='__EVENTVALIDATION' value='{MakeEV("MfaVerify")}' />" +
            "<input type='hidden' name='__EVENTTARGET' value='ctl00$cphMaster$btnVerify' />" +
            "<input type='hidden' name='__EVENTARGUMENT' value='' />" +
            "<div class='field'><label>Verification Code<br>" +
            "<input type='text' name='ctl00$cphMaster$txtCode' maxlength='6' style='width:160px;letter-spacing:6px;font-size:22px;' /></label></div>" +
            "<button class='btn' type='submit'>Verify</button></form>";
        await ctx.Response.WriteAsync(Page("MFA Verify", html));
    }
});

// Dashboard
app.MapGet("/dashboard", (HttpContext ctx) =>
{
    var uname = ctx.Session.GetString("username") ?? "Guest";
    var auth  = ctx.Session.GetString("authenticated") == "1";
    var html = auth
        ? $"<div class='msg-ok'>Authenticated as <strong>{H(uname)}</strong></div>" +
          "<h2>Dashboard</h2><ul>" +
          "<li><a href='/survey/Survey.aspx'>Survey Form (XSS in Name/Comments)</a></li>" +
          "<li><a href='/search/Search.aspx'>User Search</a></li>" +
          "<li><a href='/account/Login.aspx'>Log out</a></li></ul>"
        : "<div class='msg-warn'>Not authenticated. <a href='/account/Login.aspx'>Login</a></div>";
    return Results.Content(Page("Dashboard", html), "text/html");
});

// Survey GET
app.MapGet("/survey/Survey.aspx", (HttpContext ctx) =>
{
    var vs = MakeViewState("Survey|v1|questions=4");
    var html =
        "<h2>Customer Feedback Survey</h2>" +
        "<form method='POST' action='/survey/Survey.aspx'>" +
        $"<input type='hidden' name='__VIEWSTATE' value='{vs}' />" +
        "<input type='hidden' name='__VIEWSTATEGENERATOR' value='B2C3D4E5' />" +
        $"<input type='hidden' name='__EVENTVALIDATION' value='{MakeEV("Survey")}' />" +
        "<input type='hidden' name='__EVENTTARGET' value='' />" +
        "<input type='hidden' name='__EVENTARGUMENT' value='' />" +
        "<input type='hidden' name='ctl00_scriptManager_TSM' value='fake_tsm_token_for_testing' />" +
        "<div class='field'><label>Your Name<br><input type='text' name='ctl00$cphMain$txtName' /></label></div>" +
        "<div class='field'><label>Email<br><input type='text' name='ctl00$cphMain$txtEmail' /></label></div>" +
        "<div class='field'><label>Comments<br><textarea name='ctl00$cphMain$txtComments' rows='4'></textarea></label></div>" +
        "<div class='field'><label>Rating (1-5)<br><input type='text' name='ctl00$cphMain$txtRating' style='width:60px;' /></label></div>" +
        "<button class='btn' type='submit'>Submit Survey</button></form>" +
        "<p class='hint'>Name and Comments fields are intentionally XSS-vulnerable. Email and Rating are encoded.</p>";
    return Results.Content(Page("Survey", html), "text/html");
});

// Survey POST (intentional XSS in Name and Comments)
app.MapPost("/survey/Survey.aspx", async (HttpContext ctx) =>
{
    var form     = await ctx.Request.ReadFormAsync();
    var vs       = form["__VIEWSTATE"].ToString();
    var name     = form["ctl00$cphMain$txtName"].ToString();
    var email    = form["ctl00$cphMain$txtEmail"].ToString();
    var comments = form["ctl00$cphMain$txtComments"].ToString();
    var rating   = form["ctl00$cphMain$txtRating"].ToString();

    if (!VerifyViewState(vs))
    {
        ctx.Response.StatusCode = 500;
        await ctx.Response.WriteAsync(Page("Error", "<div class='msg-err'>ViewState MAC validation failed.</div>"));
        return;
    }

    // name and comments NOT encoded (XSS); email and rating ARE encoded
    var html =
        "<h2>Survey Submitted</h2>" +
        "<div class='msg-ok'>Thank you for your feedback!</div>" +
        "<table><tr><td style='color:#666;width:100px'>Name</td><td>" + name + "</td></tr>" +
        "<tr><td style='color:#666'>Email</td><td>" + H(email) + "</td></tr>" +
        "<tr><td style='color:#666'>Comments</td><td>" + comments + "</td></tr>" +
        "<tr><td style='color:#666'>Rating</td><td>" + H(rating) + "</td></tr></table>" +
        "<p style='margin-top:16px'><a href='/survey/Survey.aspx'>Submit another</a> | <a href='/dashboard'>Dashboard</a></p>" +
        "<p class='hint'>Name + Comments unencoded (XSS demo). Email + Rating encoded.</p>";
    await ctx.Response.WriteAsync(Page("Survey Result", html));
});

// Search (GET, reflects query param)
app.MapGet("/search/Search.aspx", (HttpContext ctx) =>
{
    var q    = ctx.Request.Query["q"].ToString();
    var hits = users.Keys.Where(u => u.Contains(q, StringComparison.OrdinalIgnoreCase)).ToList();
    var results = string.IsNullOrEmpty(q) ? "" :
        "<div style='margin-top:16px'>" +
        // Intentional: raw q reflected unencoded as query in the SQL comment
        $"<p class='hint'>Query: SELECT * FROM Users WHERE username LIKE '%{q}%'</p>" +
        (hits.Count > 0
            ? $"<div class='msg-ok'>Found: {H(string.Join(", ", hits))}</div>"
            : "<div class='msg-err'>No users found.</div>") +
        "</div>";

    var html =
        "<h2>User Search</h2>" +
        "<form method='GET' action='/search/Search.aspx'>" +
        "<div style='display:flex;gap:8px'>" +
        $"<input type='text' name='q' value='{H(q)}' placeholder='Search username...' style='flex:1' />" +
        "<button class='btn' type='submit'>Search</button></div></form>" +
        results;
    return Results.Content(Page("Search", html), "text/html");
});

// Status
app.MapGet("/status", () => Results.Json(new
{
    app = "ASP.NET Target App",
    note = "Intentionally vulnerable — DeAsp testing only",
    mac_enabled = MAC_ENABLED,
    endpoints = new[]
    {
        "GET/POST /account/Login.aspx",
        "GET/POST /account/MfaVerify.aspx  (AJAX UpdatePanel + XSS in code echo)",
        "GET      /dashboard",
        "GET/POST /survey/Survey.aspx      (XSS in Name/Comments, encoded Email/Rating)",
        "GET      /search/Search.aspx      (reflected search query)",
    },
    test_accounts = new { admin = "Password1!", user = "letmein", victim = "victim123" },
    mfa_codes     = new { admin = "123456", user = "654321", victim = "111111" },
}));

app.Run("http://0.0.0.0:7001");
