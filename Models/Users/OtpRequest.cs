namespace WebApi.Models.Users
{
    public class OtpRequest
    {
        public string Email { get; set; }
        public string OtpCode { get; set; }
    }
}
