using System;
using System.Linq;
using System.Reflection;
using DataVanger.Engine.Remediation;
using DataVanger.Engine.Remediation.Execution;
using DataVanger.Engine.Remediation.Providers;
using Xunit;

// Phase 03A — proves, by reflection over the shipped Engine assembly, that no
// production (non-simulation) remediation provider exists and that the only
// provider is the explicitly-simulation one. Combined with the executor's
// fail-closed gate (refuses non-simulation providers), this makes real
// destructive execution impossible in this phase.
public class RemediationNoRealSideEffectsTests
{
    private static readonly Assembly EngineAssembly = typeof(SimulationRemediationProvider).Assembly;

    [Fact]
    public void EveryProviderInEngine_IsSimulation()
    {
        var providerTypes = EngineAssembly.GetTypes()
            .Where(t => typeof(IRemediationProvider).IsAssignableFrom(t) && t is { IsAbstract: false, IsInterface: false })
            .ToArray();

        Assert.NotEmpty(providerTypes);

        foreach (var type in providerTypes)
        {
            var ctor = type.GetConstructor(Type.EmptyTypes);
            Assert.True(ctor is not null, $"{type.Name} should have a parameterless constructor for this audit.");
            var provider = (IRemediationProvider)ctor!.Invoke(null);
            Assert.True(provider.IsSimulation, $"{type.Name} must be a simulation provider in this phase.");
        }
    }

    [Fact]
    public void EngineExposes_OnlyTheSimulationProvider()
    {
        var providerTypes = EngineAssembly.GetTypes()
            .Where(t => typeof(IRemediationProvider).IsAssignableFrom(t) && t is { IsAbstract: false, IsInterface: false })
            .Select(t => t.Name)
            .ToArray();

        Assert.Equal(new[] { nameof(SimulationRemediationProvider) }, providerTypes);
    }

    [Fact]
    public void NoProviderTypeName_SuggestsRealOrProductionExecution()
    {
        var suspicious = EngineAssembly.GetTypes()
            .Where(t => typeof(IRemediationProvider).IsAssignableFrom(t))
            .Where(t => new[] { "Real", "Production", "Win32", "Os", "Live" }
                .Any(flag => t.Name.Contains(flag, StringComparison.OrdinalIgnoreCase)))
            .Select(t => t.Name)
            .ToArray();

        Assert.Empty(suspicious);
    }

    [Fact]
    public void ExecutorOptions_DefaultsToSimulationOnly()
        => Assert.False(RemediationExecutorOptions.Default.AllowNonSimulationProviders);
}
