using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

using MultipleAuthenticatons.Authentication.SessionID;

using MultipleAuthenticatons.Models;

namespace MultipleAuthenticatons.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ItemsController : ControllerBase
    {
        //only "SessionID" authentication schema handler should be executed.
        [Authorize(AuthenticationSchemes = SessionIDAuthenticationHandler.AuthenticationSchemeName)] 
        [HttpGet("", Name = "GetAllItems")]
        [ProducesResponseType(typeof(IEnumerable<Item>), StatusCodes.Status200OK)]
        public Task<IEnumerable<Item>> GetAll()
        {
            var items = new List<Item>
            {
                new Item
                {
                    Name = "item1"
                },
                new Item
                {
                    Name = "item2"
                }
            };
            return Task.FromResult(items.AsEnumerable());
        }
    }
}
