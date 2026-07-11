using System.Collections.Generic;
using System.Linq;
using DataVanger.Core;

namespace DataVanger.Detection.PE;

public sealed class PeAnalysisResult
{
    public bool IsPe { get; set; }
    public bool ParsedSuccessfully { get; set; }
    public string LogicalPath { get; set; } = "";
    public PeFile? File { get; set; }
    public List<Evidence> Evidence { get; } = new();
    public int Score => Evidence.Sum(e => e.ScoreDelta);

    public void Add(string description, int score, EvidenceStrength strength)
    {
        Evidence.Add(new Evidence
        {
            Category = "PE",
            Description = description,
            ScoreDelta = score,
            Strength = strength,
            CanConfirmMalware = false,
        });
    }
}
