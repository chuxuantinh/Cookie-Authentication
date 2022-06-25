using Microsoft.AspNetCore.Authentication.Cookies;

namespace CookieAuthentication
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            builder.Services.AddControllersWithViews();

            // Add Cookie-Based Authentication Service
            builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                            .AddCookie(options =>
                            {
                                // Override Paths
                                options.LoginPath = "/Auth/Login";
                                options.LogoutPath = "/Auth/Logout";
                                options.ReturnUrlParameter = "returnUrl";
                                options.AccessDeniedPath = "/Auth/Denied";

                                // HttpOnly; SameSite: Lax
                                options.Cookie.Name = "AuthToken";
                                options.Cookie.HttpOnly = true;
                                options.Cookie.SameSite = SameSiteMode.Lax;
                            });

            var app = builder.Build();


            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Error");
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            // Add AuthenticationMiddleware
            app.UseAuthentication();
            app.UseAuthorization();

            app.MapControllerRoute(
                name: "default",
                pattern: "{controller=Home}/{action=Index}/{id?}");

            app.Run();

        }
    }
}