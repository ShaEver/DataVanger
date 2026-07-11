namespace DataVanger.Infrastructure;

/// <summary>
/// Contract for a future cache store that may be considered for security-sensitive
/// reuse. Such a store must prove authenticated integrity and restricted writer
/// access (for example, an OS-protected ACL-backed store). This project currently
/// has no implementation and therefore grants no security decision from cache.
/// </summary>
public interface ICacheSecurityBoundary
{
    bool HasAuthenticatedIntegrity { get; }
    bool HasRestrictedWriterAccess { get; }
}
