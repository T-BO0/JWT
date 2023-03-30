namespace JWT.Models
{
    public class User
    {
        public int Id { get; set; }
        public string Username { get; set; } = string.Empty;
        public string Role { get; set; } = "User";
        public byte[] Passwordhash { get; set; }
        public byte[] PasswordSalt { get; set; }
        public string RefreshToken { get; set; } = string.Empty;
        public DateTime DateCreated { get; set; }
        public DateTime DateExpires { get; set; }
    }
}