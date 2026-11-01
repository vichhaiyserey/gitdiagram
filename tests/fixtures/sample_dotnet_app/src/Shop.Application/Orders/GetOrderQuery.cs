using MediatR;

namespace Shop.Application.Orders;

public record GetOrderQuery(int Id) : IRequest<string>;

public class GetOrderQueryHandler : IRequestHandler<GetOrderQuery, string>
{
    public Task<string> Handle(GetOrderQuery request, CancellationToken cancellationToken)
    {
        return Task.FromResult("order-data");
    }
}
