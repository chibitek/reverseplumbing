// ReversePlumbing PE fixture | Chibitek Engineering | 2026-10-24
// Compiled offline with Roslyn csc; see test/fixtures/pe/README.md.
using System.Reflection;
[assembly: AssemblyTitle("ReversePlumbing PE fixture")]
[assembly: AssemblyCompany("Chibitek")]
[assembly: AssemblyVersion("1.2.3.4")]
[assembly: AssemblyFileVersion("1.2.3.4")]
namespace Chibitek.ReversePlumbing.Fixture {
  public static class Probe {
    public static string Describe() => typeof(System.Net.Http.HttpClient).FullName + " " + System.Text.Json.JsonSerializer.Serialize(1);
  }
}
