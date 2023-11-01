namespace WebApi.Authorization;

using Microsoft.AspNetCore.Antiforgery;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using StackExchange.Redis;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using WebApi.Entities;
using WebApi.Helpers;

public interface IJwtUtils
{
    public string GenerateToken(User user);
    //public int? ValidateToken(string token);
    string GenerateRefreshToken(User user,string ipAddress);
}

public class JwtUtils : IJwtUtils
{
    private readonly AppSettings _appSettings;
    private readonly IConnectionMultiplexer _connectionMultiplexer;
    private readonly StackExchange.Redis.IDatabase _redisCache;

    public JwtUtils(IOptions<AppSettings> appSettings, IConnectionMultiplexer connectionMultiplexer)
    {
        _appSettings = appSettings.Value;
        _connectionMultiplexer = connectionMultiplexer;
        _redisCache = _connectionMultiplexer.GetDatabase();
    }

    public string GenerateRefreshToken(User user,string ipAddress)
    {
        _redisCache.HashSet($"RefreshToken:user{user.Id}", new HashEntry[] {
                new HashEntry("Token", $"{user.Id}." + Convert.ToBase64String(RandomNumberGenerator.GetBytes(64))),
                new HashEntry("CreatedByIp", ipAddress),
        });
        _redisCache.KeyExpire($"RefreshToken:{user.Id}",TimeSpan.FromDays(7));

        string refreshToken = _redisCache.HashGet($"RefreshToken:user{user.Id}", "Token");
        

        return refreshToken;


    }

    public string GenerateToken(User user)
    {

        var key = Encoding.ASCII.GetBytes(_appSettings.Secret);

        List<Claim> claims = new List<Claim>()
        {
            new Claim(ClaimTypes.NameIdentifier,user.Id.ToString()),
            new Claim(ClaimTypes.Role, user.Role)
        };
        JwtSecurityToken jwtSecurityToken = new JwtSecurityToken(
            issuer: "your_issuer",
            audience: "your_audience",
            claims: claims,
            expires: DateTime.UtcNow.AddDays(7),
            signingCredentials: new SigningCredentials(
                new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        );
        return new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
    }

    //public int? ValidateToken(string token)
    //{
    //    if (token == null)
    //        return null;

    //    var tokenHandler = new JwtSecurityTokenHandler();
    //    var key = Encoding.ASCII.GetBytes(_appSettings.Secret);
    //    try
    //    {
    //        tokenHandler.ValidateToken(token, new TokenValidationParameters
    //        {
    //            ValidateIssuerSigningKey = true,
    //            IssuerSigningKey = new SymmetricSecurityKey(key),
    //            //2 dòng này kiểu là có sử dụng dịch vụ ngoài ko
    //            ValidateIssuer = false,
    //            ValidateAudience = false,
    //            // set clockskew to zero so tokens expire exactly at token expiration time (instead of 5 minutes later)
    //            ClockSkew = TimeSpan.Zero
    //        }, out SecurityToken validatedToken);

    //        var jwtToken = (JwtSecurityToken)validatedToken;
    //        var userId = int.Parse(jwtToken.Claims.First(x => x.Type == "id").Value);

    //        // return user id from JWT token if validation successful
    //        return userId;
    //    }
    //    catch
    //    {
    //        // return null if validation fails
    //        return null;
    //    }
    //}
}