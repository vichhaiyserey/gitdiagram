using Microsoft.EntityFrameworkCore;
using Shop.Domain;

namespace Shop.Infrastructure;

public class AppDbContext : DbContext
{
    public DbSet<Order> Orders { get; set; } = null!;
}
