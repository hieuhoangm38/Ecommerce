using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using StackExchange.Redis;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using WebApi.Authorization;
using WebApi.Helpers;
using WebApi.Services;

var builder = WebApplication.CreateBuilder(args);

// add services to DI container
{
    var services = builder.Services;
    //var env = builder.Environment;
 
    // use sql server db in production and sqlite db in development
    
    services.AddDbContext<DataContext>();
 
    services.AddCors();
    services.AddControllers();

    // configure automapper with all automapper profiles from this assembly
    services.AddAutoMapper(typeof(Program));

    // configure strongly typed settings object
    services.Configure<AppSettings>(builder.Configuration.GetSection("AppSettings"));

    services.AddSingleton<IConnectionMultiplexer>
    (ConnectionMultiplexer.Connect(builder.Configuration.GetConnectionString("Redis")));
   
  
    services.AddScoped<IOtpUtils,OtpUtils>();
    services.AddScoped<IUserService, UserService>();
    services.AddScoped<IJwtUtils, JwtUtils>();

    services.AddAuthentication(
        option => { option.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            option.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            option.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
        }
    )
    .AddJwtBearer(otp =>
    {
        var key = Encoding.ASCII.GetBytes(builder.Configuration.GetSection("AppSettings")["Secret"]);
        otp.TokenValidationParameters = new TokenValidationParameters {
            ValidateIssuerSigningKey = true,
            ValidIssuer= "your_issuer",
            ValidAudience= "your_audience",
            IssuerSigningKey = new SymmetricSecurityKey(key),

            ValidateIssuer = true,
            ValidateAudience = true
        };
    });
    //services.AddAuthorization();
}




    var app = builder.Build();

// migrate any database changes on startup (includes initial db creation)
//using (var scope = app.Services.CreateScope())
//{
//    var dataContext = scope.ServiceProvider.GetRequiredService<DataContext>();    
//    dataContext.Database.Migrate();
//}

// configure HTTP request pipeline
{
    // global cors policy
    app.UseCors(x => x
        .AllowAnyOrigin()
        .AllowAnyMethod()
        .AllowAnyHeader());

    // global error handler
    app.UseMiddleware<ErrorHandlerMiddleware>();

    

    app.UseAuthentication();
    app.UseAuthorization();
    // custom jwt auth middleware
    //app.UseMiddleware<JwtMiddleware>();

    app.UseMiddleware<JwtAllowMiddleware>();

    app.MapControllers();
}
//
app.Run("http://0.0.0.0:4000");