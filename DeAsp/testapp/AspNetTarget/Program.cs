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
    },
    test_accounts = new { admin = "Password1!", user = "letmein", victim = "victim123" },
    mfa_codes     = new { admin = "123456", user = "654321", victim = "111111" },
}));

app.Run("http://0.0.0.0:7001");
