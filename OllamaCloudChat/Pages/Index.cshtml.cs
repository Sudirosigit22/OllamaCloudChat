using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text;
using System.Text.Json;

public class IndexModel : PageModel
{
    private readonly HttpClient _http;

    public IndexModel(IHttpClientFactory factory)
    {
        
        _http = factory.CreateClient();
    }

    public void OnGet() { }

    public async Task<IActionResult> OnPostAsync(string Message)
    {
        if (string.IsNullOrWhiteSpace(Message))
            return new JsonResult(new { answer = "" });

        try
        {
            var token = Request.Cookies["jwt"];
            var apiUrl = $"{Request.Scheme}://{Request.Host}/chat";

            var request = new HttpRequestMessage(HttpMethod.Post, apiUrl);
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

            var jsonBody = JsonSerializer.Serialize(new { Message = Message });
            request.Content = new StringContent(jsonBody, Encoding.UTF8, "application/json");

            var res = await _http.SendAsync(request);

            if (!res.IsSuccessStatusCode)
                return new JsonResult(new { answer = $"⚠️ API Error: {res.StatusCode}" });

            var responseData = await res.Content.ReadFromJsonAsync<JsonElement>();

            if (responseData.TryGetProperty("answer", out var answerProp))
            {
                return new JsonResult(new { answer = answerProp.GetString() });
            }

            return new JsonResult(new { answer = "⚠️ Format respon tidak dikenali" });
        }
        catch (Exception ex)
        {
            return new JsonResult(new { answer = "⚠️ Gagal memproses jawaban: " + ex.Message });
        }
    }
}