using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ApiAuth.Controllers
{
    [Route("api/v1/[controller]")]
    [ApiController]
    public class HomeController : ControllerBase
    {
        [HttpGet]
        [Route("anonymous")]
        [AllowAnonymous]
        public string Anonymous() => "Anônimo";

        [HttpGet]
        [Route("authenticated")]
        [Authorize]
        public string Authenticated() => "Autenticado";

        [HttpGet]
        [Route("user")]
        [Authorize(Roles = "user,admin")]
        public string User() => "Usuário, mas Administrador também pode ver";

        [HttpGet]
        [Route("admin")]
        [Authorize(Roles = "admin")]
        public string Admin() => "Administrador";
    }
}
