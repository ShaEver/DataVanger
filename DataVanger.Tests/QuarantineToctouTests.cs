using System;
using System.IO;
using System.Threading.Tasks;
using DataVanger.Engine.Quarantine;
using DataVanger.Shared.Quarantine;
using Xunit;

namespace DataVanger.Tests;

public sealed class QuarantineToctouTests
{
    [Fact]
    public async Task ChangedIdentity_NeverDeletesReplacement_AndReturnsConflict()
    {
        string path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, "original");
            var files = new ConflictFileOperations { ForceIdentityConflict = true };
            var service = NewService(files, QuarantineOptions.Production());
            var result = await service.QuarantineAsync(new QuarantineRequest
            {
                SourcePath = path,
                Classification = QuarantineThreatClassification.ConfirmedMalware,
                Origin = QuarantineRequestOrigin.Automatic,
                DeleteOriginalAfterStore = true,
            });

            Assert.Equal(QuarantineStatus.SourceIdentityConflict, result.Status);
            Assert.True(result.OriginalDeleteFailed);
            Assert.True(File.Exists(path));
            Assert.Equal(1, files.OpenCount);
            Assert.Equal(0, files.DeleteCount);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task ReparseAncestor_IsRejectedBeforeSourceRead()
    {
        string path = Path.GetTempFileName();
        try
        {
            var files = new ConflictFileOperations { ForceReparse = true };
            var result = await NewService(files, QuarantineOptions.DevelopmentSafe()).QuarantineAsync(new QuarantineRequest
            {
                SourcePath = path,
                Classification = QuarantineThreatClassification.HighRisk,
            });
            Assert.Equal(QuarantineStatus.ReparsePointRejected, result.Status);
            Assert.Equal(0, files.OpenCount);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task CurrentSingleChunkFormat_EnforcesExplicitMemoryBudget()
    {
        string path = Path.GetTempFileName();
        try
        {
            await File.WriteAllBytesAsync(path, new byte[1025]);
            var options = QuarantineOptions.DevelopmentSafe();
            options.MaxInMemoryPayloadBytes = 1024;
            var result = await NewService(new ConflictFileOperations(), options).QuarantineAsync(new QuarantineRequest
            {
                SourcePath = path,
                Classification = QuarantineThreatClassification.HighRisk,
            });
            Assert.Equal(QuarantineStatus.SourceTooLarge, result.Status);
        }
        finally { File.Delete(path); }
    }

    private static QuarantineService NewService(IQuarantineFileOperations files, QuarantineOptions options) => new(
        new InMemoryQuarantineStore(),
        new QuarantineCryptoProvider(),
        new InMemoryQuarantineKeyProtector("toctou-tests"),
        options,
        fileOperations: files);

    private sealed class ConflictFileOperations : IQuarantineFileOperations
    {
        private readonly SystemQuarantineFileOperations _inner = new();
        public bool ForceIdentityConflict { get; init; }
        public bool ForceReparse { get; init; }
        public int OpenCount { get; private set; }
        public int DeleteCount { get; private set; }
        public bool HasReparsePointInPath(string path) => ForceReparse || _inner.HasReparsePointInPath(path);
        public QuarantineSourceHandle OpenSource(string path) { OpenCount++; return _inner.OpenSource(path); }
        public bool PathReferencesIdentity(string path, QuarantineFileIdentity identity) => !ForceIdentityConflict && _inner.PathReferencesIdentity(path, identity);
        public void DeleteOpenedSource(QuarantineSourceHandle source, string path) { DeleteCount++; _inner.DeleteOpenedSource(source, path); }
    }
}
