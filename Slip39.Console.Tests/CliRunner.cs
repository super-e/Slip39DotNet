using System.Text;
using SystemConsole = System.Console;

// Every test in this assembly swaps the process-wide Console.Out/Console.Error, so no two
// of them may run at the same time.
[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace Slip39.Console.Tests;

/// <summary>
/// The result of one CLI invocation: what a script would see.
/// </summary>
/// <param name="ExitCode">The process exit code the command would have returned.</param>
/// <param name="StdOut">Everything written to standard output.</param>
/// <param name="StdErr">Everything written to standard error.</param>
public sealed record CliResult(int ExitCode, string StdOut, string StdErr)
{
    /// <summary>Both streams together, for assertions that only care that something was said.</summary>
    public string Combined => StdOut + StdErr;
}

/// <summary>
/// Drives the CLI in-process and captures exactly what a caller observes.
/// </summary>
/// <remarks>
/// These tests deliberately assert on the exit code and on which stream a message went to,
/// not just on the text. Every CLI defect this project has had was invisible to a test that
/// only checked the wording: the command printed a sensible-looking error and still exited 0,
/// so a backup script would have carried on as though it had succeeded.
/// </remarks>
public static class CliRunner
{
    public static CliResult Run(params string[] args)
    {
        var stdout = new StringWriter();
        var stderr = new StringWriter();

        var previousOut = SystemConsole.Out;
        var previousError = SystemConsole.Error;
        var previousEncoding = SystemConsole.OutputEncoding;

        try
        {
            SystemConsole.SetOut(stdout);
            SystemConsole.SetError(stderr);

            int exitCode = Program.Run(args);
            return new CliResult(exitCode, stdout.ToString(), stderr.ToString());
        }
        finally
        {
            SystemConsole.SetOut(previousOut);
            SystemConsole.SetError(previousError);
            _ = previousEncoding;
        }
    }
}
