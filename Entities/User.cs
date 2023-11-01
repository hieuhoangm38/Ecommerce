namespace WebApi.Entities;

using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

[Table("Users")]
public class User
{
    [Key]
    [Column("Id")]
    public int Id { get; set; }
    [Column("FirstName")]
    public string FirstName { get; set; }
    [Column("LastName")]
    public string LastName { get; set; }
    [Column("Email")]
    public string Email { get; set; }
    [Column("Username")]
    public string Username { get; set; }
    [Column("PasswordHash")]

    [JsonIgnore]
    public string PasswordHash { get; set; }
    [Column("Role")]
    public string Role { get; set; }

}