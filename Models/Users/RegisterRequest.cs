namespace WebApi.Models.Users;

using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;

public class RegisterRequest
{
    [Required]
    public string FirstName { get; set; }

    [Required]
    public string LastName { get; set; }
    [Required] 
    public string Email { get; set; }

    [Required]
    public string Username { get; set; }

    [Required]
    public string Password { get; set; }

    [Required]
    public string Role { get; set; }

    [Required]
    public int NumberIdentify { get; set; }
    [Required]
    public DateTime DateOfBirth { get; set; }

    [Required]
    public string Addresss { get; set; }

    

}