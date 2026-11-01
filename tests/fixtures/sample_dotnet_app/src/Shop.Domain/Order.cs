namespace Shop.Domain;

public class Order
{
    public int Id { get; set; }
    public decimal TotalAmount { get; set; }
    public string Status { get; set; } = "Pending";
}
