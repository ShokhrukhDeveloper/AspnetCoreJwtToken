using System.Security.Claims;
using jwt.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace jwt.Controller;
[ApiController]
[Route("api/[controller]")]
public class USerController:ControllerBase
{
    [HttpGet]
    [Route("Admins")]
    [Authorize(Roles="Admin")]
    public IActionResult AdminEndPoint()
    {
        var currentUser= GetCurrentUser();
        return Ok($"Hi Your name is {currentUser.UserName}  and your role is {currentUser.Role} ,anu={currentUser.anu}");
    }
    
    private UserModel? GetCurrentUser()
    {
        var identity=HttpContext.User.Identity as ClaimsIdentity;
        if(identity !=null)
        {
            
            var userClaims=identity.Claims;
            
            return new()
            {
                UserName=userClaims.FirstOrDefault(x=>x.Type==ClaimTypes.NameIdentifier).Value,
                Role=userClaims.FirstOrDefault(x=>x.Type==ClaimTypes.Role).Value,
                anu=userClaims.FirstOrDefault(x=>x.Type==ClaimTypes.Expired)?.Value??"null"

            };
        }
        return null;

    }
}