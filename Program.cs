using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

const string AuthSchema = "cookie1";
const string AuthSchema2 = "cookie2";

builder.Services.AddAuthentication(AuthSchema)
    .AddCookie(AuthSchema)
    .AddCookie(AuthSchema2);

var app = builder.Build();

app.Use((ctx, next) =>
{
    return next();
});


app.UseAuthentication();
app.MapGet("/username", (HttpContext ctx) =>
{
    return ctx.User.FindFirstValue("usr");
});

app.MapGet("/India", (HttpContext ctx) =>
{
    if (!ctx.User.Identities.Any(x => x.AuthenticationType == AuthSchema))
    {
        ctx.Response.StatusCode = 401; // 401 : not authenticate
        return "Not authenticate";
    }

    if (!ctx.User.HasClaim("passport_type", "IND"))
    {
        ctx.Response.StatusCode = 403; // 403 : not authorize
        return "Not authorize";
    }

    return "Allowed";
});

app.MapGet("/Pakistan", (HttpContext ctx) =>
{
    if (!ctx.User.Identities.Any(x => x.AuthenticationType == AuthSchema))
    {
        ctx.Response.StatusCode = 401; // 401 : not authenticate
        return "Not authenticate";
    }

    if (!ctx.User.HasClaim("passport_type", "PAK"))
    {
        ctx.Response.StatusCode = 403; // 403 : not authorize
        return "Not authorize";
    }

    return "Allowed";
});

app.MapGet("/Nepal", (HttpContext ctx) =>
{
    if (!ctx.User.Identities.Any(x => x.AuthenticationType == AuthSchema2))
    {
        ctx.Response.StatusCode = 401; // 401 : not authenticate
        return "Not authenticate";
    }

    if (!ctx.User.HasClaim("passport_type", "NEP"))
    {
        ctx.Response.StatusCode = 403; // 403 : not authorize
        return "Not authorize";
    }

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

    return "ok";
});

app.Run();