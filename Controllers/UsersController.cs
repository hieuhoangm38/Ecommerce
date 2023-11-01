namespace WebApi.Controllers;

using AutoMapper;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using MimeKit;
using StackExchange.Redis;
using System.Security.Claims;
using System.Text.RegularExpressions;
using WebApi.Authorization;
using WebApi.Entities;
using WebApi.Helpers;
using WebApi.Models.Users;
using WebApi.Services;
[Authorize]
[ApiController]
[Route("[controller]")]
public class UsersController : ControllerBase
{
    private IUserService _userService;
    private IMapper _mapper;
    private readonly AppSettings _appSettings;

    public UsersController(
        IUserService userService,
        IMapper mapper,
        IOptions<AppSettings> appSettings)
    {
        _userService = userService;
        _mapper = mapper;
        _appSettings = appSettings.Value;
    }


    [AllowAnonymous]//ko cần xác thực người dùng
    [HttpGet("get")]
    public IActionResult getString()
    {
        string response = "alo";
        return Ok(response);
    }



    [AllowAnonymous]//ko cần xác thực người dùng
    [HttpPost("authenticate")]
    public IActionResult Authenticate(AuthenticateRequest model)
    {
        string response = _userService.Authenticate(model);
        return Ok(response);
    }
    
    [AllowAnonymous] //ko cần xác thực với access token
    [HttpPost("register")]
    public IActionResult Register(RegisterRequest registerRequest)
    {

        string email = registerRequest.Email;
        if(!IsEmail(email)) 
        {
            throw new Exception("mời bạn nhập lại email theo định dạng chuẩn");
        }

        bool ketQua1 = "admin".Equals(registerRequest.Role, StringComparison.OrdinalIgnoreCase);
        bool ketQua2 = "user".Equals(registerRequest.Role, StringComparison.OrdinalIgnoreCase);

        string role = registerRequest.Role;
        if(!ketQua1 && !ketQua2)
        {
            throw new Exception("mời bạn nhập lại role");
        }
        
        string ok = _userService.Register(registerRequest);
        return Ok(ok);
    }

    [AllowAnonymous]//ko cần xác thực người dùng
    [HttpPost("verifyotp")]
    public IActionResult VerifyOtp(OtpRequest otpRequest)
    {
        string email = otpRequest.Email;
        if (!IsEmail(email))
        {
            throw new Exception("mời bạn nhập lại email theo định dạng chuẩn");
        }
        AuthenticateResponse response = _userService.VerifyOtp(otpRequest, ipAddress());
        setTokenCookie(response.RefreshToken);
        return Ok(response);
    }

    [AllowAnonymous]
    [HttpPost("refresh-token")]
    public IActionResult RefreshToken()
    {
        var refreshToken = Request.Cookies["refreshToken"];
        var response = _userService.RefreshToken(refreshToken, ipAddress());
        return Ok(response);
    }

    private void setTokenCookie(string token)
    {
        // append cookie with refresh token to the http response
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Expires = DateTime.UtcNow.AddDays(7)
        };
        Response.Cookies.Append("refreshToken", token, cookieOptions);
    }

    private string ipAddress()
    {
        // get source ip address for the current request
        if (Request.Headers.ContainsKey("X-Forwarded-For"))
            return Request.Headers["X-Forwarded-For"];
        else
            return HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString();
    }

    // cái này để test nên ko cần xác thực người dùng trong bất kì bộ điều khiển nào khi được yêu cầu
    //thuộc tính được đính kèm dưới dạng siêu giữ liệu vào Users/send/send/otpRequest metadata có thể được trích xuất 
    //sau này khi chúng ta sắp thực hiện

    //giữa thằng app.useRouting và thằng app.useEnpoint nên insert một thằng midleware vào giữa để read the metadata
    //midleware này nó sẽ đọc siêu dữ liệu được liên kết với tuyến phù hợp
    [AllowAnonymous]
    [HttpPost("send")]
    public IActionResult Send(OtpRequest otpRequest)
    {
        MimeMessage email = new MimeMessage();
        email.From.Add(MailboxAddress.Parse("joy.lang@ethereal.email"));
        email.To.Add(MailboxAddress.Parse(otpRequest.Email));
        email.Subject = "Xác minh thông tin đăng nhập";
        email.Body = new TextPart("plain")
        {
            Text = $"Mã OTP của bạn là: {otpRequest.OtpCode}"
        };

        using SmtpClient client = new SmtpClient();

        client.Connect("smtp.ethereal.email", 587, SecureSocketOptions.StartTls);
        client.Authenticate("joy.lang@ethereal.email", "uk8n6sy3cUjD5bPBgy");
        client.Send(email);
        client.Disconnect(true);
        return Ok();
    }

    [Authorize(Roles = "Admin")]
    [HttpGet]
    public IActionResult GetAll()
    {
        var users = _userService.GetAll();
        return Ok(users);
    }
    [Authorize(Roles = "User,Admin")]
    [HttpGet("getDetail")]
    public IActionResult GetById()
    {
        int id = int.Parse(HttpContext.User.FindAll(ClaimTypes.NameIdentifier).FirstOrDefault().Value);
        //check(id);
        var user = _userService.GetById(id);
        return Ok(user);
    }
    [Authorize(Roles = "User,Admin")]
    [HttpPut("putDetail")]
    public IActionResult Update(UpdateRequest model)
    {
        //check(id);
        int id = int.Parse(HttpContext.User.FindAll(ClaimTypes.NameIdentifier).FirstOrDefault().Value);
        _userService.Update(id, model);
        return Ok(new { message = "User updated successfully" });
    }
    [Authorize(Roles = "User,Admin")]
    [HttpDelete("deleteDetail")]
    public IActionResult Delete()
    {
        //check(id);
        int id = int.Parse(HttpContext.User.FindAll(ClaimTypes.NameIdentifier).FirstOrDefault().Value);
        _userService.Delete(id);
        return Ok(new { message = "User deleted successfully" });
    }



    [HttpPost("logout")]
    public IActionResult Logout()
    {
        // Lấy token từ request header hoặc cookie (tùy cách bạn lưu trữ token)
        
        int id = int.Parse(HttpContext.User.FindAll(ClaimTypes.NameIdentifier).FirstOrDefault().Value);
        //Kiểm tra xem token có tồn tại trong danh sách đen không
        //if (_blacklistService.IsTokenRevoked(token))
        //{
        //    return BadRequest("Token đã bị thu hồi."); // Token đã bị thu hồi trước đó
        //}
        _userService.Logout(id);
        // Thu hồi token 
        // Lưu ý rằng bạn cần cung cấp thông tin người dùng để đảm bảo rằng chỉ token của người dùng đó được thu hồi
        // Lấy thông tin người dùng từ token hoặc nơi lưu trữ thông tin người dùng
        /*string userId = "user_id";*/ //Thay thế bằng cách lấy thông tin người dùng
        //_blacklistService.RevokeToken(token, userId);

        // Trả về một thông báo hoặc mã trạng thái thành công
        return Ok("Bạn đã đăng xuất thành công");
    }


    //private void check(int id)
    //{
    //    var currentUser = (User)HttpContext.Items["User"];
    //    if (id != currentUser.Id && !currentUser.Role.Equals("admin", StringComparison.OrdinalIgnoreCase))
    //        throw new Exception("không có cửa");
    //}

    public bool IsEmail(string Email) => !string.IsNullOrEmpty(Email) && Regex.IsMatch(Email, @"^([\w\.\-]+)@([\w\-]+)((\.(\w){2,3})+)$");
}