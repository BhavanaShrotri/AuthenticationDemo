using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

const string AuthSchema = "cookie";

builder.Services.AddAuthentication(AuthSchema)
    .AddCookie(AuthSchema);


builder.Services.AddAuthorization(builder =>
{
    builder.AddPolicy("IND passport", pb =>
    {
        pb.RequireAuthenticatedUser()
        .AddAuthenticationSchemes(AuthSchema)
        .AddRequirements()
        .RequireClaim("passport_type", "IND");
    });
});


var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/unsecure", (HttpContext ctx) =>
{
    return ctx.User.FindFirst("usr")?.Value ?? "empty";
}).RequireAuthorization("IND passport");


app.MapGet("/username", (HttpContext ctx) =>
{
    return ctx.User.FindFirstValue("usr");
});

app.MapGet("/India", (HttpContext ctx) =>
{
    return "Allowed";
}).RequireAuthorization("IND passport"); ;

app.MapGet("/login", async (HttpContext ctx) =>
{

    var claims = new List<Claim>();
    claims.Add(new Claim("usr", "Bhavana"));
    claims.Add(new Claim("passport_type", "IND"));
    var identity = new ClaimsIdentity(claims, AuthSchema);
    var user = new ClaimsPrincipal(identity);
    await ctx.SignInAsync(AuthSchema, user);
}).AllowAnonymous();

app.Run();
