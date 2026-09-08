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

// Vuln: X-AspNet-Version / X-Powered-By disclosure on every response
app.Use(async (ctx, next) =>
{
    ctx.Response.OnStarting(() =>
    {
        ctx.Response.Headers["X-AspNet-Version"] = "4.0.30319";
        ctx.Response.Headers["X-Powered-By"] = "ASP.NET";
        ctx.Response.Headers["Server"] = "Microsoft-IIS/10.0";
        // Intentionally NO CSP / X-Frame-Options / X-Content-Type-Options / HSTS anywhere
        return Task.CompletedTask;
    });
    await next();
});

// ── Config ─────────────────────────────────────────────────────────────────
const string MACHINE_KEY = "DeAspTestKey_NotSecure_ForTestingOnly_1234567890abcdef";
const bool   MAC_ENABLED = true;    // whether a MAC is appended to outgoing ViewState
const bool   MAC_VERIFIED = true;   // whether the MAC is actually checked on the way back in —
                                     // the realistic vuln: MAC bytes are present (so a naive
                                     // "is there a MAC?" check would say "protected"), but the
                                     // server never validates them

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
    if (!MAC_ENABLED || !MAC_VERIFIED) return true;
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

// ── In-memory stored data (for stored XSS, IDOR, etc.) ────────────────────
var storedComments = new List<(string author, string body, string timestamp)>();
var userProfiles = new Dictionary<string, (string email, string phone, string role, string balance)>(StringComparer.OrdinalIgnoreCase)
{
    ["admin"]  = ("admin@corp.local", "555-0100", "Administrator", "99999.00"),
    ["user"]   = ("user@corp.local",  "555-0101", "StandardUser",  "250.00"),
    ["victim"] = ("victim@corp.local","555-0102", "StandardUser",  "1500.00"),
};
// Simulated "pending transfers" for CSRF demo
var pendingTransfers = new List<(string from, string to, string amount, string ts)>();

// ── 1. User Profile (IDOR) ─────────────────────────────────────────────────
// Vuln: hidden field 'targetUser' controls whose profile is shown — no auth check
app.MapGet("/account/Profile.aspx", (HttpContext ctx) =>
{
    var current = ctx.Session.GetString("username") ?? "guest";
    var vs = MakeViewState($"Profile|v1|{current}");
    // IDOR: shows current user's profile but form lets you change targetUser
    if (!userProfiles.TryGetValue(current, out var prof)) prof = ("unknown","unknown","unknown","0.00");
    var html =
        "<h2>My Profile</h2>" +
        $"<p class='hint'>Logged in as: <strong>{H(current)}</strong></p>" +
        "<form method='POST' action='/account/Profile.aspx'>" +
        $"<input type='hidden' name='__VIEWSTATE' value='{vs}' />" +
        $"<input type='hidden' name='__VIEWSTATEGENERATOR' value='C3D4E5F6' />" +
        $"<input type='hidden' name='__EVENTVALIDATION' value='{MakeEV("Profile")}' />" +
        // IDOR: this hidden field is user-controllable — change it to see another user's data
        $"<input type='hidden' name='ctl00$cphMaster$hdnTargetUser' value='{H(current)}' />" +
        "<div class='field'><label>Display Name<br><input type='text' name='ctl00$cphMaster$txtDisplayName' value='" + H(current) + "' /></label></div>" +
        "<div class='field'><label>Email<br><input type='text' name='ctl00$cphMaster$txtEmail' value='" + H(prof.email) + "' /></label></div>" +
        "<div class='field'><label>Phone<br><input type='text' name='ctl00$cphMaster$txtPhone' value='" + H(prof.phone) + "' /></label></div>" +
        "<button class='btn' type='submit'>Save Profile</button>" +
        "</form>" +
        "<hr/>" +
        "<h3>Account Info (read-only)</h3>" +
        "<table><tr><td style='color:#666'>Role</td><td>" + H(prof.role) + "</td></tr>" +
        "<tr><td style='color:#666'>Balance</td><td>$" + H(prof.balance) + "</td></tr></table>" +
        "<p class='hint'>VULN: hdnTargetUser hidden field is not validated — change it to view/edit any user's profile (IDOR)</p>";
    return Results.Content(Page("My Profile", html), "text/html");
});

app.MapPost("/account/Profile.aspx", async (HttpContext ctx) =>
{
    var form       = await ctx.Request.ReadFormAsync();
    var vs         = form["__VIEWSTATE"].ToString();
    // IDOR: we use the submitted targetUser, not the session user
    var targetUser = form["ctl00$cphMaster$hdnTargetUser"].ToString().Trim();
    var newEmail   = form["ctl00$cphMaster$txtEmail"].ToString();
    var newPhone   = form["ctl00$cphMaster$txtPhone"].ToString();
    var actual     = ctx.Session.GetString("username") ?? "guest";

    if (!VerifyViewState(vs))
    {
        ctx.Response.StatusCode = 500;
        await ctx.Response.WriteAsync(Page("Error", "<div class='msg-err'>ViewState MAC failed.</div>"));
        return;
    }

    bool idor = !targetUser.Equals(actual, StringComparison.OrdinalIgnoreCase);
    if (userProfiles.TryGetValue(targetUser, out var prof))
    {
        userProfiles[targetUser] = (newEmail, newPhone, prof.role, prof.balance);
        var msg = idor
            ? $"<div class='msg-warn'>⚠ IDOR: You modified <strong>{H(targetUser)}</strong>'s profile while authenticated as <strong>{H(actual)}</strong>!</div>"
            : "<div class='msg-ok'>Profile saved.</div>";
        await ctx.Response.WriteAsync(Page("Profile Saved",
            msg + $"<p>Email set to: {H(newEmail)}</p><p>Phone set to: {H(newPhone)}</p>" +
            $"<a href='/account/Profile.aspx'>Back to Profile</a>"));
    }
    else
    {
        await ctx.Response.WriteAsync(Page("Profile Saved",
            $"<div class='msg-err'>User '{H(targetUser)}' not found.</div>"));
    }
});

// ── 2. Fund Transfer (CSRF — no token) ────────────────────────────────────
// Vuln: no CSRF token — any page can POST to this and transfer funds
app.MapGet("/account/Transfer.aspx", (HttpContext ctx) =>
{
    var current = ctx.Session.GetString("username") ?? "guest";
    if (!userProfiles.TryGetValue(current, out var prof)) prof = ("","","","0.00");
    var vs = MakeViewState($"Transfer|v1|{current}");
    var recentHtml = pendingTransfers.Count == 0 ? "<p class='hint'>No transfers yet.</p>" :
        "<table><tr><td style='color:#666'>From</td><td style='color:#666'>To</td><td style='color:#666'>Amount</td><td style='color:#666'>Time</td></tr>" +
        string.Join("", pendingTransfers.TakeLast(5).Select(t =>
            $"<tr><td>{H(t.from)}</td><td>{H(t.to)}</td><td>${H(t.amount)}</td><td>{H(t.ts)}</td></tr>")) +
        "</table>";
    var html =
        "<h2>Fund Transfer</h2>" +
        $"<div class='msg-info'>Your balance: <strong>${H(prof.balance)}</strong></div>" +
        "<form method='POST' action='/account/Transfer.aspx'>" +
        // No CSRF token! Only a ViewState (which also has no CSRF protection in this demo)
        $"<input type='hidden' name='__VIEWSTATE' value='{vs}' />" +
        $"<input type='hidden' name='__VIEWSTATEGENERATOR' value='D4E5F6A7' />" +
        "<div class='field'><label>Transfer To (username)<br><input type='text' name='ctl00$cphMain$txtRecipient' /></label></div>" +
        "<div class='field'><label>Amount<br><input type='text' name='ctl00$cphMain$txtAmount' style='width:120px' /></label></div>" +
        "<div class='field'><label>Note<br><input type='text' name='ctl00$cphMain$txtNote' /></label></div>" +
        "<button class='btn' type='submit'>Transfer Funds</button>" +
        "</form>" +
        "<hr/><h3>Recent Transfers</h3>" + recentHtml +
        "<p class='hint'>VULN: No CSRF token — a malicious site can POST here and trigger a transfer on behalf of a logged-in user</p>";
    return Results.Content(Page("Transfer", html), "text/html");
});

app.MapPost("/account/Transfer.aspx", async (HttpContext ctx) =>
{
    var form      = await ctx.Request.ReadFormAsync();
    var vs        = form["__VIEWSTATE"].ToString();
    var from      = ctx.Session.GetString("username") ?? "guest";
    var recipient = form["ctl00$cphMain$txtRecipient"].ToString().Trim();
    var amount    = form["ctl00$cphMain$txtAmount"].ToString().Trim();
    var note      = form["ctl00$cphMain$txtNote"].ToString();
    var referer   = ctx.Request.Headers["Referer"].ToString();
    var isCsrf    = !string.IsNullOrEmpty(referer) && !referer.Contains("localhost:7001");

    if (!VerifyViewState(vs))
    {
        ctx.Response.StatusCode = 500;
        await ctx.Response.WriteAsync(Page("Error", "<div class='msg-err'>ViewState MAC failed.</div>"));
        return;
    }

    pendingTransfers.Add((from, recipient, amount, DateTime.UtcNow.ToString("HH:mm:ss")));
    var banner = isCsrf
        ? $"<div class='msg-err'>⚠ CSRF detected! Transfer of ${H(amount)} to {H(recipient)} was triggered from an external origin ({H(referer)}) — but was still processed because there is no CSRF protection!</div>"
        : $"<div class='msg-ok'>Transfer of ${H(amount)} to {H(recipient)} initiated. Note: {H(note)}</div>";
    await ctx.Response.WriteAsync(Page("Transfer Result",
        banner + $"<a href='/account/Transfer.aspx'>Back</a>"));
});

// ── 3. Admin Panel (ViewState parameter tampering) ─────────────────────────
// Vuln: role is stored in ViewState — tamper VS to get admin access
app.MapGet("/admin/Panel.aspx", (HttpContext ctx) =>
{
    var current = ctx.Session.GetString("username") ?? "guest";
    var role    = ctx.Request.Query["role"].ToString();
    if (string.IsNullOrEmpty(role)) role = "user";
    // Role is embedded in ViewState — no server-side role check on VS decode
    var vs = MakeViewState($"Admin|v1|role={role}|user={current}");
    var html =
        "<h2>Admin Panel</h2>" +
        "<form method='POST' action='/admin/Panel.aspx'>" +
        $"<input type='hidden' name='__VIEWSTATE' value='{vs}' />" +
        $"<input type='hidden' name='__VIEWSTATEGENERATOR' value='E5F6A7B8' />" +
        $"<input type='hidden' name='__EVENTVALIDATION' value='{MakeEV("Admin")}' />" +
        $"<input type='hidden' name='ctl00$cphAdmin$hdnRole' value='{H(role)}' />" +
        "<div class='field'><label>Action<br><select name='ctl00$cphAdmin$ddlAction' style='width:100%;padding:8px;border:1px solid #ccc;border-radius:4px'>" +
        "<option>View Users</option><option>Reset Password</option><option>Delete Account</option><option>Promote to Admin</option>" +
        "</select></label></div>" +
        "<div class='field'><label>Target Username<br><input type='text' name='ctl00$cphAdmin$txtTarget' /></label></div>" +
        "<button class='btn' type='submit'>Execute</button>" +
        "</form>" +
        $"<p class='hint'>Current role from ViewState: <strong>{H(role)}</strong></p>" +
        "<p class='hint'>VULN: Role is read from hidden field hdnRole (not from session). Change it to 'Administrator' to bypass the admin check below.</p>";
    return Results.Content(Page("Admin Panel", html), "text/html");
});

app.MapPost("/admin/Panel.aspx", async (HttpContext ctx) =>
{
    var form   = await ctx.Request.ReadFormAsync();
    var vs     = form["__VIEWSTATE"].ToString();
    var role   = form["ctl00$cphAdmin$hdnRole"].ToString();   // read from hidden field — not session!
    var action = form["ctl00$cphAdmin$ddlAction"].ToString();
    var target = form["ctl00$cphAdmin$txtTarget"].ToString();
    var actual = ctx.Session.GetString("username") ?? "guest";

    if (!VerifyViewState(vs))
    {
        ctx.Response.StatusCode = 500;
        await ctx.Response.WriteAsync(Page("Error", "<div class='msg-err'>ViewState MAC failed.</div>"));
        return;
    }

    // Auth check uses the SUBMITTED role, not the session role — vulnerable
    if (!role.Equals("Administrator", StringComparison.OrdinalIgnoreCase))
    {
        await ctx.Response.WriteAsync(Page("Access Denied",
            "<div class='msg-err'>Access denied. Administrator role required.</div>" +
            $"<p class='hint'>Your submitted role: '{H(role)}'. Change hdnRole to 'Administrator' to bypass.</p>" +
            "<a href='/admin/Panel.aspx'>Try again</a>"));
        return;
    }

    var result = (action, target) switch
    {
        ("View Users", _)       => $"Users: {string.Join(", ", users.Keys)}",
        ("Reset Password", var t) => userProfiles.ContainsKey(t) ? $"Password reset for {t}" : $"User '{t}' not found",
        ("Delete Account", var t) => userProfiles.ContainsKey(t) ? $"Account '{t}' deleted (simulated)" : $"User '{t}' not found",
        ("Promote to Admin", var t) => userProfiles.ContainsKey(t) ? $"'{t}' promoted to admin" : $"User '{t}' not found",
        _ => "Unknown action"
    };
    await ctx.Response.WriteAsync(Page("Admin Result",
        $"<div class='msg-warn'>⚠ Role bypass successful — executed as '{H(actual)}' with forged role '{H(role)}'</div>" +
        $"<div class='msg-ok'>Action: {H(action)} → {H(result)}</div>" +
        "<a href='/admin/Panel.aspx'>Back</a>"));
});

// ── 4. Comments (Stored XSS) ──────────────────────────────────────────────
// Vuln: comments stored unencoded, reflected to all visitors
app.MapGet("/community/Comments.aspx", (HttpContext ctx) =>
{
    var vs = MakeViewState("Comments|v1");
    var commentsHtml = storedComments.Count == 0
        ? "<p class='hint'>No comments yet.</p>"
        : string.Join("", storedComments.Select(c =>
            // STORED XSS: body not encoded
            $"<div style='border:1px solid #eee;border-radius:4px;padding:12px;margin-bottom:8px'>" +
            $"<strong>{H(c.author)}</strong> <span style='color:#888;font-size:11px'>{H(c.timestamp)}</span><br>" +
            $"<div style='margin-top:6px'>{c.body}</div>" +   // unencoded!
            $"</div>"));
    var html =
        "<h2>Community Comments</h2>" +
        "<div id='commentList'>" + commentsHtml + "</div>" +
        "<hr/>" +
        "<h3>Leave a Comment</h3>" +
        "<form method='POST' action='/community/Comments.aspx'>" +
        $"<input type='hidden' name='__VIEWSTATE' value='{vs}' />" +
        $"<input type='hidden' name='__VIEWSTATEGENERATOR' value='F6A7B8C9' />" +
        $"<input type='hidden' name='__EVENTVALIDATION' value='{MakeEV("Comments")}' />" +
        "<div class='field'><label>Name<br><input type='text' name='ctl00$cphMain$txtName' /></label></div>" +
        "<div class='field'><label>Comment<br><textarea name='ctl00$cphMain$txtComment' rows='3'></textarea></label></div>" +
        "<button class='btn' type='submit'>Post Comment</button>" +
        "</form>" +
        "<p class='hint'>VULN: Comment body is stored and rendered unencoded — stored XSS. Try: &lt;img src=x onerror=alert(document.cookie)&gt;</p>";
    return Results.Content(Page("Comments", html), "text/html");
});

app.MapPost("/community/Comments.aspx", async (HttpContext ctx) =>
{
    var form    = await ctx.Request.ReadFormAsync();
    var vs      = form["__VIEWSTATE"].ToString();
    var author  = form["ctl00$cphMain$txtName"].ToString().Trim();
    var comment = form["ctl00$cphMain$txtComment"].ToString(); // not sanitized

    if (!VerifyViewState(vs))
    {
        ctx.Response.StatusCode = 500;
        await ctx.Response.WriteAsync(Page("Error", "<div class='msg-err'>ViewState MAC failed.</div>"));
        return;
    }

    if (!string.IsNullOrWhiteSpace(author) && !string.IsNullOrWhiteSpace(comment))
        storedComments.Add((author, comment, DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss")));

    ctx.Response.Redirect("/community/Comments.aspx");
});

// ── 5. Open Redirect ──────────────────────────────────────────────────────
// Vuln: returnUrl param not validated — redirect to any external site
app.MapGet("/account/Redirect.aspx", (HttpContext ctx) =>
{
    var returnUrl = ctx.Request.Query["returnUrl"].ToString();
    if (!string.IsNullOrEmpty(returnUrl))
    {
        // No validation — open redirect
        ctx.Response.Redirect(returnUrl);
        return Results.Empty;
    }
    var html =
        "<h2>Redirect Demo</h2>" +
        "<p>Use <code>?returnUrl=https://evil.com</code> to trigger open redirect.</p>" +
        "<p class='hint'>VULN: No URL validation on returnUrl parameter.</p>" +
        "<form method='GET' action='/account/Redirect.aspx'>" +
        "<div style='display:flex;gap:8px'>" +
        "<input type='text' name='returnUrl' placeholder='https://...' style='flex:1' />" +
        "<button class='btn' type='submit'>Go</button></div></form>";
    return Results.Content(Page("Redirect", html), "text/html");
});

// ── 6. Password Change (no old-password check + CSRF) ─────────────────────
// Vuln: doesn't require old password, no CSRF token
app.MapGet("/account/ChangePassword.aspx", (HttpContext ctx) =>
{
    var current = ctx.Session.GetString("username") ?? "guest";
    var vs = MakeViewState($"ChangePwd|v1|{current}");
    var html =
        "<h2>Change Password</h2>" +
        "<form method='POST' action='/account/ChangePassword.aspx'>" +
        $"<input type='hidden' name='__VIEWSTATE' value='{vs}' />" +
        $"<input type='hidden' name='__VIEWSTATEGENERATOR' value='A8B9C0D1' />" +
        // VULN: no old password field — just set a new one
        // CSRF: no token, so a malicious page can change your password
        "<div class='field'><label>New Password<br><input type='password' name='ctl00$cphMaster$txtNewPassword' /></label></div>" +
        "<div class='field'><label>Confirm Password<br><input type='password' name='ctl00$cphMaster$txtConfirm' /></label></div>" +
        "<button class='btn' type='submit'>Change Password</button>" +
        "</form>" +
        "<p class='hint'>VULN 1: No current password required. VULN 2: No CSRF token — malicious page can change your password.</p>";
    return Results.Content(Page("Change Password", html), "text/html");
});

app.MapPost("/account/ChangePassword.aspx", async (HttpContext ctx) =>
{
    var form     = await ctx.Request.ReadFormAsync();
    var vs       = form["__VIEWSTATE"].ToString();
    var newPwd   = form["ctl00$cphMaster$txtNewPassword"].ToString();
    var confirm  = form["ctl00$cphMaster$txtConfirm"].ToString();
    var uname    = ctx.Session.GetString("username") ?? "guest";
    var referer  = ctx.Request.Headers["Referer"].ToString();
    var isCsrf   = !string.IsNullOrEmpty(referer) && !referer.Contains("localhost:7001");

    if (!VerifyViewState(vs))
    {
        ctx.Response.StatusCode = 500;
        await ctx.Response.WriteAsync(Page("Error", "<div class='msg-err'>ViewState MAC failed.</div>"));
        return;
    }

    if (newPwd != confirm)
    {
        await ctx.Response.WriteAsync(Page("Change Password", "<div class='msg-err'>Passwords do not match.</div><a href='/account/ChangePassword.aspx'>Try again</a>"));
        return;
    }

    if (users.ContainsKey(uname))
        users[uname] = (Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(newPwd))), users[uname].mfa);

    var banner = isCsrf
        ? $"<div class='msg-err'>⚠ CSRF! Password for {H(uname)} changed by a request from {H(referer)} — no CSRF protection!</div>"
        : $"<div class='msg-ok'>Password for {H(uname)} changed successfully.</div>";
    await ctx.Response.WriteAsync(Page("Password Changed", banner + "<a href='/dashboard'>Dashboard</a>"));
});

// ── 7. Report Generator (AJAX, multi-UpdatePanel) ─────────────────────────
// Tests DeAsp multi-UpdatePanel parsing and param injection
app.MapGet("/reports/Report.aspx", (HttpContext ctx) =>
{
    var vs = MakeViewState("Report|v1|multi");
    var tsm = string.Join("%3A", Enumerable.Range(0, 20).Select(_ => Guid.NewGuid().ToString("N")[..8]));
    var html =
        "<h2>Report Generator</h2>" +
        "<form method='POST' action='/reports/Report.aspx' id='reportForm'>" +
        $"<input type='hidden' name='ctl00$scriptManager' value='ctl00$cphMain$ScriptManager1' />" +
        $"<input type='hidden' name='ctl00_ScriptManager1_TSM' value='{tsm}' />" +
        $"<input type='hidden' name='__VIEWSTATE' value='{vs}' />" +
        $"<input type='hidden' name='__VIEWSTATEGENERATOR' value='B9C0D1E2' />" +
        $"<input type='hidden' name='__EVENTVALIDATION' value='{MakeEV("Report")}' />" +
        "<input type='hidden' name='__EVENTTARGET' value='' />" +
        "<input type='hidden' name='__EVENTARGUMENT' value='' />" +
        "<input type='hidden' name='__ASYNCPOST' value='true' />" +
        "<div class='field'><label>Report Type<br><select name='ctl00$cphMain$ddlReportType' style='width:100%;padding:8px;border:1px solid #ccc;border-radius:4px'>" +
        "<option value='users'>User Report</option>" +
        "<option value='transactions'>Transaction Report</option>" +
        "<option value='audit'>Audit Log</option>" +
        "</select></label></div>" +
        "<div class='field'><label>Filter (username or date)<br><input type='text' name='ctl00$cphMain$txtFilter' /></label></div>" +
        "<div class='field'><label>Format<br><select name='ctl00$cphMain$ddlFormat' style='width:100%;padding:8px;border:1px solid #ccc;border-radius:4px'>" +
        "<option>HTML</option><option>CSV</option><option>JSON</option>" +
        "</select></label></div>" +
        "<button class='btn' type='submit' name='ctl00$cphMain$btnGenerate' value='Generate'>Generate Report</button>" +
        "</form>" +
        "<div id='ctl00_cphMain_pnlStatus'></div>" +
        "<div id='ctl00_cphMain_pnlResults'></div>" +
        "<p class='hint'>Posts as AJAX UpdatePanel — tests multi-panel response parsing in DeAsp</p>";
    return Results.Content(Page("Reports", html), "text/html");
});

app.MapPost("/reports/Report.aspx", async (HttpContext ctx) =>
{
    var form       = await ctx.Request.ReadFormAsync();
    var vs         = form["__VIEWSTATE"].ToString();
    var reportType = form["ctl00$cphMain$ddlReportType"].ToString();
    var filter     = form["ctl00$cphMain$txtFilter"].ToString();
    var format     = form["ctl00$cphMain$ddlFormat"].ToString();
    var isAjax     = form["__ASYNCPOST"].ToString() == "true";

    if (!VerifyViewState(vs))
    {
        ctx.Response.StatusCode = 500;
        await ctx.Response.WriteAsync(isAjax
            ? "43|error|500|ViewState MAC validation failed.|"
            : Page("Error", "<div class='msg-err'>ViewState MAC failed.</div>"));
        return;
    }

    // Build two separate UpdatePanel results
    var statusHtml =
        "<div id='ctl00_cphMain_pnlStatus_inner'>" +
        $"<div class='msg-info'>Generating {H(reportType)} report" +
        (string.IsNullOrEmpty(filter) ? "" : $" filtered by '{filter}'") +  // unencoded filter
        $" in {H(format)} format…</div></div>";

    var reportData = reportType switch
    {
        "users" => string.Join("", users.Keys.Where(u => string.IsNullOrEmpty(filter) || u.Contains(filter, StringComparison.OrdinalIgnoreCase))
                      .Select(u => $"<tr><td>{H(u)}</td><td>{H(userProfiles.GetValueOrDefault(u).role)}</td><td>{H(userProfiles.GetValueOrDefault(u).email)}</td></tr>")),
        "transactions" => string.Join("", pendingTransfers
                      .Where(t => string.IsNullOrEmpty(filter) || t.from.Contains(filter) || t.to.Contains(filter))
                      .Select(t => $"<tr><td>{H(t.from)}</td><td>{H(t.to)}</td><td>${H(t.amount)}</td><td>{H(t.ts)}</td></tr>")),
        "audit" => $"<tr><td>{DateTime.UtcNow:HH:mm:ss}</td><td>report_generated</td><td>{H(ctx.Session.GetString("username") ?? "guest")}</td></tr>",
        _ => "<tr><td>unknown</td></tr>"
    };

    var resultsHtml =
        "<div id='ctl00_cphMain_pnlResults_inner'>" +
        $"<h3>{H(reportType)} Report</h3>" +
        "<table style='border:1px solid #eee'>" +
        "<tr style='background:#f5f5f5'><th style='padding:6px 12px'>Col1</th><th style='padding:6px 12px'>Col2</th><th style='padding:6px 12px'>Col3</th></tr>" +
        (string.IsNullOrEmpty(reportData) ? "<tr><td colspan='3' style='padding:8px;color:#888'>No data</td></tr>" : reportData) +
        "</table></div>";

    var newVs = MakeViewState($"Report|v2|{DateTime.UtcNow.Ticks}");
    var s1 = "$('#ctl00_cphMain_btnGenerate').prop('disabled',false);";

    if (isAjax)
    {
        var sb = new StringBuilder();
        sb.Append($"{statusHtml.Length}|updatePanel|ctl00_cphMain_pnlStatus|{statusHtml}|");
        sb.Append($"{resultsHtml.Length}|updatePanel|ctl00_cphMain_pnlResults|{resultsHtml}|");
        sb.Append($"{newVs.Length}|hiddenField|__VIEWSTATE|{newVs}|");
        sb.Append("8|hiddenField|__VIEWSTATEGENERATOR|B9C0D1E2|");
        sb.Append("1|hiddenField|__SCROLLPOSITIONX|0|");
        sb.Append("1|hiddenField|__SCROLLPOSITIONY|0|");
        sb.Append("0|asyncPostBackControlIDs||");
        sb.Append("31|updatePanelIDs||tctl00$cphMain$pnlStatus,tctl00$cphMain$pnlResults,|");
        sb.Append("3|asyncPostBackTimeout||600|");
        sb.Append("22|formAction||./Report.aspx|");
        sb.Append($"{s1.Length}|scriptStartupBlock|ScriptContentNoTags|{s1}|");
        ctx.Response.ContentType = "text/plain; charset=utf-8";
        ctx.Response.Headers["X-AspNet-Version"] = "4.0.30319";
        await ctx.Response.WriteAsync(sb.ToString());
    }
    else
    {
        await ctx.Response.WriteAsync(Page("Report", statusHtml + resultsHtml));
    }
});

// ── 8. Debug endpoint (information disclosure) ────────────────────────────
// Vuln: exposes internal state, machine key, session data
app.MapGet("/elmah.axd", (HttpContext ctx) =>
{
    var html =
        "<h2>ELMAH Error Log (Debug Mode)</h2>" +
        "<div class='msg-warn'>⚠ This endpoint should be protected in production!</div>" +
        "<h3>Application Config</h3>" +
        "<table>" +
        $"<tr><td style='color:#666'>MachineKey (partial)</td><td><code>{MACHINE_KEY[..16]}…</code></td></tr>" +
        $"<tr><td style='color:#666'>MAC Enabled</td><td>{MAC_ENABLED}</td></tr>" +
        $"<tr><td style='color:#666'>Server Time</td><td>{DateTime.UtcNow:O}</td></tr>" +
        $"<tr><td style='color:#666'>Active Users</td><td>{string.Join(", ", users.Keys)}</td></tr>" +
        $"<tr><td style='color:#666'>Stored Comments</td><td>{storedComments.Count}</td></tr>" +
        $"<tr><td style='color:#666'>Pending Transfers</td><td>{pendingTransfers.Count}</td></tr>" +
        "</table>" +
        "<p class='hint'>VULN: Information disclosure — debug endpoint accessible without auth</p>";
    return Results.Content(Page("Debug / ELMAH", html), "text/html");
});

// Also common ASP.NET debug paths
app.MapGet("/trace.axd", (HttpContext ctx) =>
    Results.Content(Page("Trace", "<h2>Application Trace</h2><div class='msg-warn'>Trace enabled — exposes request details</div>" +
        $"<p>Request: {H(ctx.Request.Method)} {H(ctx.Request.Path)}</p>" +
        $"<p>Session ID: {H(ctx.Session.Id)}</p>" +
        $"<p>Username: {H(ctx.Session.GetString("username") ?? "none")}</p>"), "text/html"));

// ═════════════════════════════════════════════════════════════════════════
// BATCH 2 — broader OWASP + ASP.NET-specific coverage
// ═════════════════════════════════════════════════════════════════════════

var passwordResetTokens = new Dictionary<string, (string user, long issuedTicks)>();
var registeredUsers = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "admin", "user", "victim" };

// ── 9. ViewState cleartext info leak (isAdmin flag readable without decrypting) ──
app.MapGet("/account/Preferences.aspx", (HttpContext ctx) =>
{
    var current = ctx.Session.GetString("username") ?? "guest";
    var isAdmin = current.Equals("admin", StringComparison.OrdinalIgnoreCase);
    // VULN: sensitive flag embedded directly in the ViewState payload string —
    // MAC prevents *tampering* but does NOT prevent *reading* it (no encryption)
    var vs = MakeViewState($"Prefs|v1|user={current}|isAdmin={isAdmin}|theme=light");
    var html =
        "<h2>Preferences</h2>" +
        "<form method='POST' action='/account/Preferences.aspx'>" +
        $"<input type='hidden' name='__VIEWSTATE' value='{vs}' />" +
        $"<input type='hidden' name='__EVENTVALIDATION' value='{MakeEV("Prefs")}' />" +
        "<div class='field'><label>Theme<br><select name='ctl00$cphMain$ddlTheme' style='width:100%;padding:8px;border:1px solid #ccc;border-radius:4px'>" +
        "<option>light</option><option>dark</option></select></label></div>" +
        "<button class='btn' type='submit'>Save</button></form>" +
        "<p class='hint'>VULN: ViewState is MAC-protected (tamper-proof) but NOT encrypted — " +
        "decode it and you'll see 'isAdmin=" + isAdmin + "' in cleartext. EnableViewStateMac without " +
        "viewStateEncryptionMode='Always' leaks sensitive server state to anyone who can view page source.</p>";
    return Results.Content(Page("Preferences", html), "text/html");
});
app.MapPost("/account/Preferences.aspx", async (HttpContext ctx) =>
{
    var form = await ctx.Request.ReadFormAsync();
    if (!VerifyViewState(form["__VIEWSTATE"].ToString()))
    {
        ctx.Response.StatusCode = 500;
        await ctx.Response.WriteAsync(Page("Error", "<div class='msg-err'>ViewState MAC failed.</div>"));
        return;
    }
    await ctx.Response.WriteAsync(Page("Saved", "<div class='msg-ok'>Preferences saved.</div><a href='/account/Preferences.aspx'>Back</a>"));
});

// ── 10. Debug stack trace disclosure ────────────────────────────────────────
app.MapGet("/debug/ThrowError.aspx", (HttpContext ctx) =>
{
    var crash = ctx.Request.Query["crash"].ToString();
    if (crash == "1")
    {
        try { throw new InvalidOperationException("Simulated unhandled exception: division by zero in ReportEngine.CalculateTotals()"); }
        catch (Exception ex)
        {
            ctx.Response.StatusCode = 500;
            var trace =
                $"[InvalidOperationException: {H(ex.Message)}]\n" +
                "   AspNetTarget.ReportEngine.CalculateTotals() +142\n" +
                "   AspNetTarget.Controllers.ReportController.Generate(ReportRequest req) +88\n" +
                "   System.Web.Mvc.ActionMethodDispatcher.Execute(ControllerContext cc, Object[] p) +23\n" +
                "   System.Web.Mvc.Async.AsyncControllerActionInvoker.<>c__DisplayClass1.<BeginInvokeSynchronousActionMethod>b__1() +12";
            return Results.Content(
                "<h1>Server Error in '/' Application.</h1>" +
                $"<h2>{H(ex.Message)}</h2>" +
                "<p>Description: An unhandled exception occurred during the execution of the current web request. " +
                "Please review the stack trace for more information about the error and where it originated in the code.</p>" +
                "<h3>Stack Trace:</h3>" +
                $"<pre style='background:#f5f5f5;padding:12px;border:1px solid #ccc;font-size:12px'>{H(trace)}</pre>" +
                "<hr/><p><b>Version Information:</b> Microsoft .NET Framework Version:4.0.30319; ASP.NET Version:4.8.4670.0</p>",
                "text/html");
        }
    }
    return Results.Content(Page("Debug", "<h2>Debug Endpoint</h2><p>Try <code>?crash=1</code></p><p class='hint'>VULN: customErrors=Off style — full stack trace + framework version disclosed to unauthenticated users.</p>"), "text/html");
});

// ── 11. web.config / backup file exposure ───────────────────────────────────
app.MapGet("/web.config", () => Results.Content(
    "<?xml version=\"1.0\"?>\n<configuration>\n  <connectionStrings>\n" +
    "    <add name=\"MainDB\" connectionString=\"Server=sql01.corp.local;Database=AppDb;User Id=sa;Password=P@ssw0rd_2024!;\" />\n" +
    "  </connectionStrings>\n  <system.web>\n    <machineKey validationKey=\"" + MACHINE_KEY + "\" decryptionKey=\"AUTOGENERATED\" validation=\"HMACSHA1\" />\n" +
    "    <compilation debug=\"true\" targetFramework=\"4.8\" />\n    <customErrors mode=\"Off\" />\n  </system.web>\n</configuration>",
    "application/xml"));
app.MapGet("/web.config.bak", () => Results.Redirect("/web.config"));
app.MapGet("/files/backup.zip", () => Results.Content("PK\x03\x04 [simulated zip binary — contains db_backup_2024.sql, web.config, appsettings.Production.json]", "application/zip"));
app.MapGet("/files/", () => Results.Content(Page("Index of /files/",
    "<h2>Index of /files/</h2><table>" +
    "<tr><td><a href='/files/backup.zip'>backup.zip</a></td><td>2024-01-15</td></tr>" +
    "<tr><td><a href='/files/Download.aspx'>Download.aspx</a></td><td>2024-01-15</td></tr>" +
    "<tr><td><a href='/files/db_export.csv'>db_export.csv</a></td><td>2024-02-01</td></tr>" +
    "</table><p class='hint'>VULN: Directory listing enabled — reveals backup files not meant to be public.</p>"), "text/html"));

// ── 12. Session fixation ─────────────────────────────────────────────────────
app.MapGet("/account/SetSession.aspx", (HttpContext ctx) =>
{
    // VULN: accepts an attacker-supplied session identifier from the query string
    // and binds it into the session store without regenerating on login
    var sid = ctx.Request.Query["sid"].ToString();
    var html = string.IsNullOrEmpty(sid)
        ? "<h2>Session Fixation Demo</h2><p>Use <code>?sid=ATTACKER_CHOSEN_ID</code></p>"
        : $"<h2>Session Fixation Demo</h2><div class='msg-warn'>Session cookie set to attacker-chosen value: <strong>{H(sid)}</strong></div>" +
          "<p>If a victim now logs in using this link, their authenticated session will use the SAME session ID the attacker already knows.</p>";
    if (!string.IsNullOrEmpty(sid))
        ctx.Response.Cookies.Append("ASP.NET_SessionId", sid);
    return Results.Content(Page("Session Fixation", html +
        "<p class='hint'>VULN: Session ID accepted from an untrusted source and not regenerated on privilege change (login).</p>"), "text/html");
});

// ── 13. SQL injection (error-based simulation) ──────────────────────────────
app.MapGet("/product/Details.aspx", (HttpContext ctx) =>
{
    var sku = ctx.Request.Query["sku"].ToString();
    var html = "<h2>Product Details</h2>" +
        "<form method='GET' action='/product/Details.aspx'><div style='display:flex;gap:8px'>" +
        $"<input type='text' name='sku' value='{H(sku)}' placeholder='Product SKU e.g. SKU-1001' style='flex:1' />" +
        "<button class='btn' type='submit'>Lookup</button></div></form>";

    if (!string.IsNullOrEmpty(sku))
    {
        // Simulated raw SQL string concatenation (never actually executed)
        var simulatedQuery = $"SELECT Id,Name,Price FROM Products WHERE Sku = '{sku}'";
        bool hasQuote = sku.Contains('\'');
        bool hasUnion = sku.Contains("UNION", StringComparison.OrdinalIgnoreCase);
        html += $"<p class='hint'>Query: {H(simulatedQuery)}</p>";

        if (hasQuote && !hasUnion)
        {
            html += "<div class='msg-err'>System.Data.SqlClient.SqlException: Unclosed quotation mark after the character string ''. " +
                    $"Incorrect syntax near '{H(sku)}'.</div>";
        }
        else if (hasUnion && sku.Contains("SELECT", StringComparison.OrdinalIgnoreCase))
        {
            html += "<div class='msg-warn'>⚠ UNION-based injection succeeded (simulated):</div>" +
                    "<table><tr><th>Id</th><th>Name</th><th>Price</th></tr>" +
                    "<tr><td>1</td><td>Widget</td><td>9.99</td></tr>" +
                    "<tr><td>injected</td><td>admin:5f4dcc3b5aa765d61d8327deb882cf99</td><td>N/A</td></tr></table>";
        }
        else if (sku == "SKU-1001")
        {
            html += "<table><tr><th>Id</th><th>Name</th><th>Price</th></tr><tr><td>1</td><td>Widget</td><td>9.99</td></tr></table>";
        }
        else
        {
            html += "<div class='msg-err'>No product found.</div>";
        }
    }
    html += "<p class='hint'>VULN: SQL injection — try <code>SKU-1001'</code> or <code>' UNION SELECT username,password,3 FROM Users--</code></p>";
    return Results.Content(Page("Product", html), "text/html");
});

// ── 14. OS command injection (simulated) ────────────────────────────────────
app.MapGet("/admin/Ping.aspx", (HttpContext ctx) =>
{
    var vs = MakeViewState("Ping|v1");
    var html =
        "<h2>Network Diagnostic Tool</h2>" +
        "<form method='POST' action='/admin/Ping.aspx'>" +
        $"<input type='hidden' name='__VIEWSTATE' value='{vs}' />" +
        "<div class='field'><label>Host<br><input type='text' name='ctl00$cphAdmin$txtHost' placeholder='8.8.8.8' /></label></div>" +
        "<button class='btn' type='submit'>Ping</button></form>" +
        "<p class='hint'>VULN: Try <code>8.8.8.8 &amp;&amp; whoami</code> or <code>; cat /etc/passwd</code></p>";
    return Results.Content(Page("Ping Tool", html), "text/html");
});
app.MapPost("/admin/Ping.aspx", async (HttpContext ctx) =>
{
    var form = await ctx.Request.ReadFormAsync();
    if (!VerifyViewState(form["__VIEWSTATE"].ToString()))
    {
        ctx.Response.StatusCode = 500;
        await ctx.Response.WriteAsync(Page("Error", "<div class='msg-err'>ViewState MAC failed.</div>"));
        return;
    }
    var host = form["ctl00$cphAdmin$txtHost"].ToString();
    // Simulated shell-out (never actually executed) — string concatenation into a shell command
    var simulatedCmd = $"/bin/ping -c 1 {host}";
    var injected = host.IndexOfAny(new[] { ';', '&', '|', '`', '$' }) >= 0;
    var output = injected
        ? "<div class='msg-warn'>⚠ Command injection executed (simulated):</div><pre style='background:#f5f5f5;padding:12px'>uid=33(www-data) gid=33(www-data) groups=33(www-data)\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin</pre>"
        : $"<div class='msg-ok'>PING {H(host)}: 1 packets transmitted, 1 received, 0% loss</div>";
    await ctx.Response.WriteAsync(Page("Ping Result",
        $"<p class='hint'>Command: {H(simulatedCmd)}</p>" + output + "<a href='/admin/Ping.aspx'>Back</a>"));
});

// ── 15. Path traversal / LFI ─────────────────────────────────────────────────
var virtualFiles = new Dictionary<string, string>
{
    ["report1.txt"] = "Q3 Sales Report\n---------------\nRevenue: $1.2M\nGrowth: 14%",
    ["notes.txt"]   = "Meeting notes: discuss Q4 roadmap.",
};
app.MapGet("/files/Download.aspx", (HttpContext ctx) =>
{
    var file = ctx.Request.Query["file"].ToString();
    var html = "<h2>File Download</h2>" +
        "<form method='GET' action='/files/Download.aspx'><div style='display:flex;gap:8px'>" +
        $"<input type='text' name='file' value='{H(file)}' placeholder='report1.txt' style='flex:1' />" +
        "<button class='btn' type='submit'>Download</button></div></form>";

    if (!string.IsNullOrEmpty(file))
    {
        // VULN: no path canonicalization/allowlist check — traversal sequences pass through
        var traversal = file.Contains("..") || file.Contains("%2e%2e", StringComparison.OrdinalIgnoreCase);
        if (traversal && (file.Contains("web.config") || file.Contains("machineKey")))
        {
            html += "<div class='msg-warn'>⚠ Path traversal succeeded (simulated read of ../../web.config):</div>" +
                    $"<pre style='background:#f5f5f5;padding:12px;font-size:11px'>&lt;machineKey validationKey=\"{H(MACHINE_KEY)}\" validation=\"HMACSHA1\" /&gt;</pre>";
        }
        else if (traversal)
        {
            html += "<div class='msg-warn'>⚠ Path traversal detected — file outside webroot would be readable in a real deployment.</div>";
        }
        else if (virtualFiles.TryGetValue(file, out var content))
        {
            html += $"<pre style='background:#f5f5f5;padding:12px'>{H(content)}</pre>";
        }
        else
        {
            html += "<div class='msg-err'>File not found.</div>";
        }
    }
    html += "<p class='hint'>VULN: Try <code>../../web.config</code> or <code>..%2f..%2fweb.config</code></p>";
    return Results.Content(Page("Download", html), "text/html");
});

// ── 16. SSRF ──────────────────────────────────────────────────────────────────
app.MapGet("/internal/secret", () => Results.Content(
    "INTERNAL-ONLY ENDPOINT — flag: SSRF{internal_network_reachable_via_avatar_fetch}", "text/plain"));

app.MapGet("/tools/FetchUrl.aspx", async (HttpContext ctx) =>
{
    var url = ctx.Request.Query["url"].ToString();
    var html = "<h2>Avatar Fetcher</h2><p>Fetch a profile picture from a URL (server-side).</p>" +
        "<form method='GET' action='/tools/FetchUrl.aspx'><div style='display:flex;gap:8px'>" +
        $"<input type='text' name='url' value='{H(url)}' placeholder='https://example.com/avatar.png' style='flex:1' />" +
        "<button class='btn' type='submit'>Fetch</button></div></form>";

    if (!string.IsNullOrEmpty(url))
    {
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
            var resp = await http.GetAsync(url);
            var body = await resp.Content.ReadAsStringAsync();
            html += $"<div class='msg-info'>Status: {(int)resp.StatusCode}</div>" +
                    $"<pre style='background:#f5f5f5;padding:12px;max-height:200px;overflow:auto'>{H(body[..Math.Min(body.Length, 500)])}</pre>";
        }
        catch (Exception ex)
        {
            html += $"<div class='msg-err'>Fetch failed: {H(ex.Message)}</div>";
        }
    }
    html += "<p class='hint'>VULN: No allowlist on target host — server will fetch any URL including internal-only endpoints. " +
            "Try <code>http://localhost:7001/internal/secret</code> or <code>http://localhost:7001/elmah.axd</code></p>";
    return Results.Content(Page("SSRF Demo", html), "text/html");
});

// ── 17. Account enumeration + predictable password-reset token ─────────────
app.MapGet("/account/ForgotPassword.aspx", (HttpContext ctx) =>
{
    var html =
        "<h2>Forgot Password</h2>" +
        "<form method='POST' action='/account/ForgotPassword.aspx'>" +
        "<div class='field'><label>Username<br><input type='text' name='ctl00$cphMaster$txtUsername' /></label></div>" +
        "<button class='btn' type='submit'>Send Reset Link</button></form>" +
        "<p class='hint'>VULN: response differs for valid vs invalid usernames (account enumeration), and the reset token is a predictable base64(username:timestamp).</p>";
    return Results.Content(Page("Forgot Password", html), "text/html");
});
app.MapPost("/account/ForgotPassword.aspx", async (HttpContext ctx) =>
{
    var form  = await ctx.Request.ReadFormAsync();
    var uname = form["ctl00$cphMaster$txtUsername"].ToString().Trim();
    var host  = ctx.Request.Headers["Host"].ToString();   // used unsanitized below — host header injection

    if (users.ContainsKey(uname))
    {
        var ticks = DateTime.UtcNow.Ticks;
        // VULN: predictable token — base64(username:ticks), no HMAC, no expiry enforcement shown
        var token = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{uname}:{ticks}"));
        passwordResetTokens[token] = (uname, ticks);
        // VULN: reset link built from the raw Host header — host header injection / poisoning risk
        var resetLink = $"https://{host}/account/ResetPassword.aspx?token={Uri.EscapeDataString(token)}";
        await ctx.Response.WriteAsync(Page("Reset Link Sent",
            $"<div class='msg-ok'>A password reset link has been sent to the email on file for '{H(uname)}'.</div>" +
            $"<p class='hint'>(Demo only — normally emailed, shown here for testing) Reset link: <br><code style='word-break:break-all'>{H(resetLink)}</code></p>" +
            $"<p class='hint'>VULN: Host header was reflected unsanitized into the reset link — try setting <code>Host: evil.com</code> and re-submitting.</p>"));
    }
    else
    {
        // VULN: different response — allows username enumeration
        await ctx.Response.WriteAsync(Page("User Not Found",
            $"<div class='msg-err'>No account found with username '{H(uname)}'.</div>"));
    }
});
app.MapGet("/account/ResetPassword.aspx", (HttpContext ctx) =>
{
    var token = ctx.Request.Query["token"].ToString();
    if (passwordResetTokens.TryGetValue(token, out var info))
    {
        var vs = MakeViewState($"Reset|v1|{info.user}");
        var html =
            $"<h2>Reset Password for {H(info.user)}</h2>" +
            "<form method='POST' action='/account/ResetPassword.aspx'>" +
            $"<input type='hidden' name='__VIEWSTATE' value='{vs}' />" +
            $"<input type='hidden' name='token' value='{H(token)}' />" +
            "<div class='field'><label>New Password<br><input type='password' name='ctl00$cphMaster$txtNewPassword' /></label></div>" +
            "<button class='btn' type='submit'>Reset</button></form>";
        return Results.Content(Page("Reset Password", html), "text/html");
    }
    return Results.Content(Page("Invalid Token", "<div class='msg-err'>Invalid or expired token.</div>"), "text/html");
});
app.MapPost("/account/ResetPassword.aspx", async (HttpContext ctx) =>
{
    var form  = await ctx.Request.ReadFormAsync();
    var token = form["token"].ToString();
    var newPwd = form["ctl00$cphMaster$txtNewPassword"].ToString();
    if (passwordResetTokens.TryGetValue(token, out var info) && users.ContainsKey(info.user))
    {
        users[info.user] = (Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(newPwd))), users[info.user].mfa);
        passwordResetTokens.Remove(token);
        await ctx.Response.WriteAsync(Page("Password Reset", $"<div class='msg-ok'>Password for {H(info.user)} has been reset.</div><a href='/account/Login.aspx'>Login</a>"));
    }
    else
    {
        await ctx.Response.WriteAsync(Page("Error", "<div class='msg-err'>Invalid token.</div>"));
    }
});

// ── 18. Weak registration — no password policy, no rate limit ──────────────
app.MapGet("/account/Register.aspx", () =>
{
    var html =
        "<h2>Create Account</h2>" +
        "<form method='POST' action='/account/Register.aspx'>" +
        "<div class='field'><label>Username<br><input type='text' name='ctl00$cphMaster$txtNewUsername' /></label></div>" +
        "<div class='field'><label>Password<br><input type='password' name='ctl00$cphMaster$txtNewPassword' /></label></div>" +
        "<button class='btn' type='submit'>Register</button></form>" +
        "<p class='hint'>VULN: No password complexity requirement (try '1'), no CAPTCHA, no rate limiting — scriptable mass account creation.</p>";
    return Results.Content(Page("Register", html), "text/html");
});
app.MapPost("/account/Register.aspx", async (HttpContext ctx) =>
{
    var form  = await ctx.Request.ReadFormAsync();
    var uname = form["ctl00$cphMaster$txtNewUsername"].ToString().Trim();
    var pwd   = form["ctl00$cphMaster$txtNewPassword"].ToString();

    if (string.IsNullOrWhiteSpace(uname) || string.IsNullOrWhiteSpace(pwd))
    {
        await ctx.Response.WriteAsync(Page("Register", "<div class='msg-err'>Username and password required.</div>"));
        return;
    }
    if (registeredUsers.Contains(uname))
    {
        await ctx.Response.WriteAsync(Page("Register", $"<div class='msg-err'>Username '{H(uname)}' already taken.</div>"));
        return;
    }
    registeredUsers.Add(uname);
    users[uname] = (Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(pwd))), "000000");
    await ctx.Response.WriteAsync(Page("Registered",
        $"<div class='msg-ok'>Account '{H(uname)}' created with password length {pwd.Length} (no policy enforced).</div>" +
        "<a href='/account/Login.aspx'>Login</a>"));
});

// ── 19. CORS misconfiguration on a JSON API ─────────────────────────────────
app.MapGet("/api/account-data", (HttpContext ctx) =>
{
    var current = ctx.Session.GetString("username") ?? "guest";
    // VULN: reflects arbitrary Origin + allows credentials — any site can read this
    // authenticated user's data via a cross-origin fetch(..., {credentials:'include'})
    var origin = ctx.Request.Headers["Origin"].ToString();
    ctx.Response.Headers["Access-Control-Allow-Origin"] = string.IsNullOrEmpty(origin) ? "*" : origin;
    ctx.Response.Headers["Access-Control-Allow-Credentials"] = "true";
    ctx.Response.Headers["Access-Control-Allow-Methods"] = "GET, POST";
    userProfiles.TryGetValue(current, out var prof);
    return Results.Json(new { username = current, email = prof.email, phone = prof.phone, role = prof.role, balance = prof.balance });
});

// ── 20. HTTP Parameter Pollution on role assignment ─────────────────────────
app.MapPost("/admin/Panel2.aspx", async (HttpContext ctx) =>
{
    // Reads raw body to demonstrate duplicate-key handling: role=user&role=Administrator
    using var reader = new StreamReader(ctx.Request.Body);
    var raw = await reader.ReadToEndAsync();
    var pairs = raw.Split('&').Select(p => p.Split('=')).Where(p => p.Length == 2)
                   .Select(p => (k: Uri.UnescapeDataString(p[0]).Replace('+',' '), v: Uri.UnescapeDataString(p[1]).Replace('+',' '))).ToList();
    var roleValues = pairs.Where(p => p.k == "role").Select(p => p.v).ToList();
    // VULN: takes the LAST value like many parsers do — client can smuggle role=user&role=Administrator
    // past a naive first-match WAF/validation layer while the app itself uses the last value
    var effectiveRole = roleValues.LastOrDefault() ?? "user";
    var html = $"<h2>HTTP Parameter Pollution Demo</h2>" +
        $"<p>Received {roleValues.Count} 'role' values: {H(string.Join(", ", roleValues))}</p>" +
        $"<p>Effective role (last value wins): <strong>{H(effectiveRole)}</strong></p>" +
        (effectiveRole.Equals("Administrator", StringComparison.OrdinalIgnoreCase)
            ? "<div class='msg-warn'>⚠ Admin access granted via HPP</div>"
            : "<div class='msg-ok'>Standard user access</div>") +
        "<p class='hint'>VULN: Try POST body <code>role=user&amp;role=Administrator</code> — a security gateway checking only the first value would miss this.</p>";
    return Results.Content(Page("HPP Demo", html), "text/html");
});
app.MapGet("/admin/Panel2.aspx", () => Results.Content(Page("HPP Demo",
    "<h2>HTTP Parameter Pollution Demo</h2><p>POST <code>role=user&amp;role=Administrator</code> to <code>/admin/Panel2.aspx</code></p>"), "text/html"));

// ── 21. Insecure cookie flags ─────────────────────────────────────────────────
app.MapGet("/account/RememberMe.aspx", (HttpContext ctx) =>
{
    var current = ctx.Session.GetString("username") ?? "guest";
    // VULN: no HttpOnly, no Secure, no SameSite — readable by JS, sent over HTTP, sent cross-site
    ctx.Response.Cookies.Append("RememberMeToken", $"{current}:{Guid.NewGuid():N}", new CookieOptions
    {
        HttpOnly = false,
        Secure = false,
        SameSite = SameSiteMode.None,
        Expires = DateTimeOffset.UtcNow.AddDays(30),
    });
    return Results.Content(Page("Remember Me",
        "<div class='msg-ok'>Remember-me cookie set.</div>" +
        "<p class='hint'>VULN: Cookie set without HttpOnly/Secure/SameSite — check the Set-Cookie header. " +
        "Contrast with ASP.NET_SessionId, which the framework sets more safely by default.</p>"), "text/html");
});

// ── Status (updated) ───────────────────────────────────────────────────────
app.MapGet("/status", () => Results.Json(new
{
    app = "ASP.NET Target App",
    note = "Intentionally vulnerable — DeAsp testing only",
    mac_enabled = MAC_ENABLED,
    endpoints = new[]
    {
        "GET/POST /account/Login.aspx",
        "GET/POST /account/MfaVerify.aspx       AJAX UpdatePanel + XSS in code echo",
        "GET      /dashboard",
        "GET/POST /account/Profile.aspx          IDOR via hdnTargetUser hidden field",
        "GET/POST /account/Transfer.aspx         CSRF — no token on fund transfer",
        "GET/POST /account/ChangePassword.aspx   CSRF + no current-password check",
        "GET/POST /admin/Panel.aspx              Role bypass via hdnRole hidden field",
        "GET/POST /community/Comments.aspx       Stored XSS in comment body",
        "GET      /account/Redirect.aspx         Open redirect via returnUrl",
        "GET/POST /survey/Survey.aspx            Reflected XSS in Name/Comments",
        "GET      /search/Search.aspx            Reflected search query",
        "GET/POST /reports/Report.aspx           Multi-UpdatePanel AJAX + XSS in filter",
        "GET      /elmah.axd                     Info disclosure — machineKey partial",
        "GET      /trace.axd                     Trace endpoint — session data",
        "GET/POST /account/Preferences.aspx      ViewState cleartext isAdmin leak (MAC != encryption)",
        "GET      /debug/ThrowError.aspx?crash=1  Stack trace + framework version disclosure",
        "GET      /web.config                    Config file exposure (connection string, machineKey)",
        "GET      /files/backup.zip, /files/      Exposed backup + directory listing",
        "GET      /account/SetSession.aspx?sid=   Session fixation",
        "GET      /product/Details.aspx?sku=      SQL injection (error-based + UNION)",
        "GET/POST /admin/Ping.aspx                OS command injection",
        "GET      /files/Download.aspx?file=      Path traversal / LFI",
        "GET      /tools/FetchUrl.aspx?url=       SSRF (try target /internal/secret)",
        "GET/POST /account/ForgotPassword.aspx    Account enumeration + predictable reset token + host-header injection",
        "GET/POST /account/ResetPassword.aspx     (paired with ForgotPassword)",
        "GET/POST /account/Register.aspx          No password policy, no rate limiting",
        "GET      /api/account-data               CORS misconfig — reflected Origin + credentials",
        "GET/POST /admin/Panel2.aspx              HTTP Parameter Pollution (duplicate role=)",
        "GET      /account/RememberMe.aspx        Insecure cookie flags (no HttpOnly/Secure/SameSite)",
        "(passive) all responses                  X-AspNet-Version/X-Powered-By/Server disclosed; no CSP/XFO/XCTO/HSTS anywhere",
    },
    test_accounts = new { admin = "Password1!", user = "letmein", victim = "victim123" },
    mfa_codes     = new { admin = "123456", user = "654321", victim = "111111" },
}));

app.Run("http://0.0.0.0:7001");
