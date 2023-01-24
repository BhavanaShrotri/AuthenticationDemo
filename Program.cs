using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

const string AuthSchema = "cookie";

builder.Services.AddAuthentication(AuthSchema)
    .AddCookie(AuthSchema);

var app = builder.Build();

app.UseAuthentication();

app.Use((ctx, next) =>
{
    if (ctx.Request.Path.StartsWithSegments("/login"))
    {
        return next();
    }

    if (!ctx.User.Identities.Any(x => x.AuthenticationType == AuthSchema))
    {
        ctx.Response.StatusCode = 401; // 401 : not authenticate
        return Task.CompletedTask;
    }

    if (!ctx.User.HasClaim("passport_type", "IND"))
    {
        ctx.Response.StatusCode = 403; // 403 : not authorize
        return Task.CompletedTask;
    }

    return next();
});


app.MapGet("/unsecure", (HttpContext ctx) =>
{
    return ctx.User.FindFirst("usr")?.Value ?? "empty";
});


app.MapGet("/username", (HttpContext ctx) =>
{
    return ctx.User.FindFirstValue("usr");
});

app.MapGet("/India", (HttpContext ctx) =>
{
    //if (!ctx.User.Identities.Any(x => x.AuthenticationType == AuthSchema))
    //{
    //    ctx.Response.StatusCode = 401; // 401 : not authenticate
    //    return "Not authenticate";
    //}

    //if (!ctx.User.HasClaim("passport_type", "IND"))
    //{
    //    ctx.Response.StatusCode = 403; // 403 : not authorize
    //    return "Not authorize";
    //}

    return "Allowed";
});

app.MapGet("/Pakistan", (HttpContext ctx) =>
{
    //if (!ctx.User.Identities.Any(x => x.AuthenticationType == AuthSchema))
    //{
    //    ctx.Response.StatusCode = 401; // 401 : not authenticate
    //    return "Not authenticate";
    //}

    //if (!ctx.User.HasClaim("passport_type", "PAK"))
    //{
    //    ctx.Response.StatusCode = 403; // 403 : not authorize
    //    return "Not authorize";
    //}

    return "Allowed";
});

app.MapGet("/Nepal", (HttpContext ctx) =>
{
    //if (!ctx.User.Identities.Any(x => x.AuthenticationType == AuthSchema2))
    //{
    //    ctx.Response.StatusCode = 401; // 401 : not authenticate
    //    return "Not authenticate";
    //}

    //if (!ctx.User.HasClaim("passport_type", "NEP"))
    //{
    //    ctx.Response.StatusCode = 403; // 403 : not authorize
    //    return "Not authorize";
    //}

    return "Allowed";
});


app.MapGet("/login", async (HttpContext ctx) =>
{

    var claims = new List<Claim>();
    claims.Add(new Claim("usr", "Bhavana"));
    claims.Add(new Claim("passport_type", "IND"));
    var identity = new ClaimsIdentity(claims, AuthSchema);
    var user = new ClaimsPrincipal(identity);
    await ctx.SignInAsync(AuthSchema, user);
});

app.Run();