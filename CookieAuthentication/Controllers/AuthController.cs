using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace CookieAuthentication.Controllers
{
    public class AuthController : Controller
    {
        public IActionResult Login(string? returnUrl)
        {
            return View();
        }
        
        [HttpPost]
        public async Task<IActionResult> Login(string username, string password, string? returnUrl)
        {
            if (!ModelState.IsValid)
                return BadRequest();

            /* -- Solution-Specific Credential Validation Start -- */

            if (username != "tinh" || password != "1234")
                return View();

            /* -- Solution-Specific Credential Validation End   -- */
            var claims = new List<Claim>
            {
                // Define claims for logged user
                new Claim("Name", username)
            };
            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var authProperties = new AuthenticationProperties
            {
                AllowRefresh = true,
                ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(30),
                IssuedUtc = DateTimeOffset.UtcNow,
            };

            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(identity), authProperties);

            // Actually this is not safe
            // Check returnUrl is in a domain of the solution. 
            return Redirect(returnUrl ?? "/");
        }

        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }
    }
}
