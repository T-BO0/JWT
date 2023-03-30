using JWT.Models;
using Microsoft.EntityFrameworkCore;

namespace JWT.Data
{
    public class DataContext : DbContext
    {
        public DataContext(DbContextOptions options) : base(options)
        {
        }
        
        public DbSet<User> Users { get; set; }
    }
}