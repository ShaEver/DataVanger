using DataVanger.Memory;
using DataVanger.Runtime.Amsi;

namespace DataVanger.Tests;

public sealed class RuntimeLibraryExtractionTests
{
    [Xunit.Fact]
    public void MemoryAndAmsiRuntimeTypes_LiveOutsideTheWpfAssembly()
    {
        Xunit.Assert.Equal("DataVanger.Infrastructure", typeof(MemoryScannerEngine).Assembly.GetName().Name);
        Xunit.Assert.Equal("DataVanger.Infrastructure", typeof(MemoryBehavioralBridge).Assembly.GetName().Name);
        Xunit.Assert.Equal("DataVanger.Infrastructure", typeof(InMemoryAmsiProvider).Assembly.GetName().Name);
    }

    [Xunit.Fact]
    public void ServiceAssembly_DoesNotReferenceTheWpfAssembly()
    {
        var references = typeof(DataVanger.Service.Runtime.DataVangerServiceRuntime)
            .Assembly
            .GetReferencedAssemblies();

        Xunit.Assert.DoesNotContain(
            references,
            reference => string.Equals(reference.Name, "DataVanger", StringComparison.Ordinal));
    }
}
