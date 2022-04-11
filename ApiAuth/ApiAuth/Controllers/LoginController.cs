using ApiAuth.Models;
using ApiAuth.Models.Requests;
using ApiAuth.Repositories;
using ApiAuth.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Threading.Tasks;

namespace ApiAuth.Controllers
{
    [Route("api/v1/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        [HttpPost]
        [Route("login")]
        public async Task<ActionResult<dynamic>> AuthenticateAsync([FromBody] User model) 
        {
            // Recupera o usuário
            User user = UserRepository.Get(model.UserName, model.Password);

            if (user == null) return NotFound("Usuário ou senha inválidos");

            string token = TokenService.GenerateToken(user);
            string refreshToken = TokenService.GenerateRefreshToken();
            TokenService.SaveRefreshToken(user.UserName, refreshToken);

            user.Password = "";

            return Ok(new
            {
                user = user,
                access_token = token,
                refresh_token = refreshToken,
            });
        }

        [HttpPost]
        [Route("refresh")]
        public IActionResult Refresh([FromBody]RefreshTokenRequest request)
        {
            ClaimsPrincipal principal = TokenService.GetPrincipalFromExpiredToken(request.Token);
            string username = principal.Identity.Name;
            string savedRefreshToken = TokenService.GetRefreshToken(username);

            if (savedRefreshToken != request.RefreshToken)
                throw new SecurityTokenException("Invalid Token");

            string newJwtToken = TokenService.GenerateToken(principal.Claims);
            string newRefreshToken = TokenService.GenerateRefreshToken();
            TokenService.DeleteRefreshToken(username);
            TokenService.SaveRefreshToken(username, newRefreshToken);

            return Ok(new 
            { 
                token = newJwtToken,
                refresh_token = newRefreshToken,
            });
        }
    }
}
