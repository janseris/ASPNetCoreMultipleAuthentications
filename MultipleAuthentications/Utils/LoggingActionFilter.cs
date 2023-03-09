using Microsoft.AspNetCore.Mvc.Filters;

namespace MultipleAuthenticatons.Utils
{
    public class LoggingActionFilter : IActionFilter
    {
        public void OnActionExecuting(ActionExecutingContext context)
        {
            Console.WriteLine($"Calling {context.HttpContext.Request.Path}");
        }
        public void OnActionExecuted(ActionExecutedContext context)
        {
            Console.WriteLine($"Finished {context.HttpContext.Request.Path} call");
        }
    }
}
