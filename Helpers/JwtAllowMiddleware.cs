using StackExchange.Redis;
using System.Security.Claims;
using WebApi.Entities;

namespace WebApi.Helpers
{
    public class JwtAllowMiddleware
    {

        private readonly RequestDelegate _next;
        private readonly IConnectionMultiplexer _connectionMultiplexer;
        private readonly StackExchange.Redis.IDatabase _redisCache;


        public JwtAllowMiddleware
        (
            RequestDelegate next,
            IConnectionMultiplexer connectionMultiplexer
        ) 
        {
            _next = next;
            _connectionMultiplexer = connectionMultiplexer;
            _redisCache = _connectionMultiplexer.GetDatabase();
        }

        public async Task Invoke(HttpContext context)
        {
            // Kiểm tra xem token đã bị đưa vào danh sách đen (blacklist) chưa
            var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();
            //int? id = int.Parse(context.User.FindAll(ClaimTypes.NameIdentifier).FirstOrDefault()?.Value);

            if (string.IsNullOrEmpty(token))
            {
                // Nếu token là null, cho phép yêu cầu đi tiếp qua middleware
                await _next(context);
                return;
            }

            if (_redisCache.StringGet($"AllowList:user{int.Parse(context.User.FindAll(ClaimTypes.NameIdentifier).FirstOrDefault()?.Value)}") == token)
            {
                await _next(context);
                return;
            }
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"message\": \"Unauthorized\"}");

        }

    }
}
