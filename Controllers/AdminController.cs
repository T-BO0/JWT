using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JWT.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AdminController : ControllerBase
    {
        [HttpGet("random-number"), Authorize(Roles = "Admin")]
        public async Task<ActionResult<int>> GetRandomNumber()
        {
            var random = new Random();
            var num = random.Next(0,100);
            return Ok(num);
        }


        [HttpGet("get-me-name"), Authorize]
        public ActionResult<object> GetMeName()
        {
            var user = User.Identity.Name;
            var role = User.FindFirstValue(ClaimTypes.Role);
            return Ok(new {user, role});
        }
    }
}