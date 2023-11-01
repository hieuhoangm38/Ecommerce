using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace WebApi.Entities
{
    [Table("Identify")]
    public class Identify
    {
        [Key]
        [Column("Number")]
        public int NumberIdentify { get; set; }
        [Column("DateOfBirth")]
        public DateTime DateOfBirth { get; set; }
        [Column("Addresss")]
        public string Addresss { get; set; }
        [Column("UserId")]
        public int UserId { get; set; }
        //public User User { get; set; }
    }
}
